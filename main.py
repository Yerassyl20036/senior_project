from mininet.log import setLogLevel, info
from mn_wifi.net import Mininet_wifi
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference
from mininet.node import RemoteController
from containernet.node import Docker
import networkx as nx
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
import requests
import csv
from pathlib import Path
from eth_account import Account
from web3 import Web3
import os

# IN ORDER TO CLEAN UP THE NETWORK FIRST RUN
# sudo mn -c

# ------------------------------------------------------------------------------
# 1) CREATE CUSTOM TOPOLOGY
# ------------------------------------------------------------------------------
def create_custom_topology():
    """
     - 3x3 torus of OVS switches (9 switches)
     - 3 Wi-Fi access points
     - 6 or more stations (regular hosts)
     - 2 Docker hosts
    """
    net = Mininet_wifi(controller=RemoteController,
                       link=wmediumd,
                       wmediumd_mode=interference)

    info("\n*** Creating 9 OVS switches for a 3x3 torus ***\n")
    switches = []
    for r in range(3):
        row = []
        for c in range(3):
            idx = r*3 + c + 1
            sw_name = f"s{idx}"
            sw = net.addSwitch(sw_name, protocols='OpenFlow13')
            row.append(sw)
        switches.append(row)

    info("*** Linking switches in a torus pattern ***\n")
    for r in range(3):
        for c in range(3):
            sw_curr = switches[r][c]
            sw_right = switches[r][(c+1)%3]
            sw_down = switches[(r+1)%3][c]
            # Link horizontally
            if c < 2:
                net.addLink(sw_curr, sw_right)
            elif c == 2:
                net.addLink(sw_curr, switches[r][0])
            # Link vertically
            if r < 2:
                net.addLink(sw_curr, sw_down)
            elif r == 2:
                net.addLink(sw_curr, switches[0][c])

    info("\n*** Creating 3 Wi-Fi Access Points ***\n")
    ap1 = net.addAccessPoint('ap1', ssid='ssid-ap1', mode='g', channel='1',
                             position='10,10,0')
    ap2 = net.addAccessPoint('ap2', ssid='ssid-ap2', mode='g', channel='6',
                             position='20,10,0')
    ap3 = net.addAccessPoint('ap3', ssid='ssid-ap3', mode='g', channel='11',
                             position='30,10,0')

    info("\n*** Creating 6 stations (regular hosts) ***\n")
    sta_list = []
    for i in range(1, 7):
        sta = net.addStation(f'sta{i}', position=f'{10+2*i},15,0')
        sta_list.append(sta)

    info("\n*** Creating 2 Docker-based hosts ***\n")
    # Make sure you have a valid Docker image (dimage='ubuntu:trusty' or custom)
    d1 = net.addHost('d1',
                       dimage='ubuntu:trusty',
                       docker_args={'cpus': '0.5'})
    d2 = net.addHost('d2',
                       dimage='ubuntu:trusty',
                       docker_args={'cpus': '0.5'})

    info("\n*** Adding a Remote Controller ***\n")
    c0 = net.addController('c0', controller=RemoteController,
                           ip='127.0.0.1', port=6653)

    info("\n*** Configuring Wi-Fi ***\n")
    net.configureWifiNodes()

    info("*** Linking APs to some switches ***\n")
    # e.g., link ap1-> s5, ap2-> s6, ap3-> s9
    s5 = switches[1][1]  # middle
    s6 = switches[1][2]
    s9 = switches[2][2]
    net.addLink(ap1, s5)
    net.addLink(ap2, s6)
    net.addLink(ap3, s9)

    info("*** Linking Docker hosts to top-left corner (s1) and top-center (s2) ***\n")
    s1 = switches[0][0]
    s2 = switches[0][1]
    net.addLink(d1, s1)
    net.addLink(d2, s2)

    info("\n*** Starting network (but we won't start here) ***\n")
    return net

# ------------------------------------------------------------------------------
# 2) VISUALIZATION FUNCTION
# ------------------------------------------------------------------------------
class FloodlightVisualizer:
    def __init__(
        self,
        device_url="http://localhost:8080/wm/device/",
        links_url="http://localhost:8080/wm/topology/links/json",
        dpid_map=None,
        stations_map=None,
        docker_hosts_map=None
    ):
        """
        dpid_map: mapping from DPIDs -> label (e.g. {"1000000000000001": "ap1"})
        stations_map: map from IP -> station name (e.g. {"10.0.0.2": "sta2"})
        docker_hosts_map: map from IP -> docker name (e.g. {"10.0.0.4": "d1"})
        """
        self.device_url = device_url
        self.links_url  = links_url

        self.topology   = nx.Graph()
        self.dpid_map   = dpid_map if dpid_map else {}
        self.stations_map = stations_map if stations_map else {}
        self.docker_hosts_map = docker_hosts_map if docker_hosts_map else {}

    def fetch_json(self, url):
        """ Safely GET JSON from Floodlight, with error handling """
        try:
            resp = requests.get(url, timeout=5)
        except requests.exceptions.RequestException as e:
            print(f"[Error] Failed to connect to {url}: {e}")
            return None

        if resp.status_code != 200:
            print(f"[Error] {url} returned status {resp.status_code}")
            print("Response text:", resp.text)
            return None

        try:
            return resp.json()
        except ValueError as e:
            print("[Error] Could not parse JSON:", e)
            print("Response text:", resp.text)
            return None

    def remap_dpid(self, dpid_str):
        """
        If dpid_str is in self.dpid_map, return the mapped name (e.g. "ap1"),
        otherwise default to "s{dpid_str}".
        """
        if dpid_str in self.dpid_map:
            return self.dpid_map[dpid_str]
        else:
            return f"s{dpid_str}"

    def add_switch_links(self):
        data = self.fetch_json(self.links_url)
        if not data or not isinstance(data, list):
            print("[Warning] /wm/topology/links/json returned invalid data.")
            return

        for link in data:
            src_dpid = link.get("src-switch", "")
            dst_dpid = link.get("dst-switch", "")
            if not src_dpid or not dst_dpid:
                continue

            src_label = self.remap_dpid(src_dpid)
            dst_label = self.remap_dpid(dst_dpid)

            self.topology.add_node(src_label, type="switch")
            self.topology.add_node(dst_label, type="switch")

            link_type = link.get("type", "")  # e.g. "internal"/"external"
            direction = link.get("direction", "")

            self.topology.add_edge(
                src_label,
                dst_label,
                src_port=link.get("src-port"),
                dst_port=link.get("dst-port"),
                link_type=link_type,
                direction=direction
            )

    def add_hosts(self):
        data = self.fetch_json(self.device_url)
        if not data:
            print("[Warning] /wm/device/ returned no data.")
            return

        if isinstance(data, dict) and "devices" in data:
            devices = data["devices"]
        elif isinstance(data, list):
            devices = data
        else:
            print("[Warning] /wm/device/ had unexpected JSON shape.")
            return

        for dev in devices:
            if not isinstance(dev, dict):
                continue

            mac_list = dev.get("mac", [])  # sometimes a list
            # Could be e.g. ["00:11:22:33:44:55"]
            # or a single string
            if isinstance(mac_list, str):
                mac_list = [mac_list]

            ipv4_list = dev.get("ipv4", [])
            ap_list = dev.get("attachmentPoint", [])

            if not ap_list or not isinstance(ap_list, list):
                continue

            ap = ap_list[0]
            switch_dpid = ap.get("switch") or ap.get("switchDPID")
            port = ap.get("port")
            if not switch_dpid or port is None:
                continue

            # We'll pick the first IPv4 if present
            if ipv4_list:
                ip = ipv4_list[0]  # e.g. "10.0.0.2"
            else:
                ip = None

            # Build host label & type
            # 1) If IP is in self.stations_map => that is "staX"
            # 2) If IP is in self.docker_hosts_map => "dX"
            # 3) else => "h<ip>" if ip, or "h<mac>" fallback

            if ip and ip in self.stations_map:
                host_label = self.stations_map[ip]       # e.g. "sta2"
                host_type  = "station"
            elif ip and ip in self.docker_hosts_map:
                host_label = self.docker_hosts_map[ip]   # e.g. "d1"
                host_type  = "dockerhost"
            else:
                # fallback
                if ip:
                    host_label = f"h{ip}"               # "h10.0.0.2"
                else:
                    # fallback to MAC if no IP
                    if mac_list:
                        host_label = f"h{mac_list[0]}"
                    else:
                        host_label = "hUnknown"
                host_type = "host"

            self.topology.add_node(host_label, type=host_type)

            # Now remap the switch’s dpid
            switch_label = self.remap_dpid(switch_dpid)
            # Mark it type="switch"
            self.topology.add_node(switch_label, type="switch")

            # Host <-> Switch edge
            self.topology.add_edge(
                host_label,
                switch_label,
                port=port
            )

    def build_topology(self):
        """Build the topology from Floodlight data, then classify node types."""
        self.add_switch_links()
        self.add_hosts()
        self.classify_nodes()

    def classify_nodes(self):
        """
        If a node_name starts with "ap", we label it as "ap".
        If it starts with "sta", label as station.
        If it starts with "d", label as dockerhost, etc.

        But if we already assigned "station"/"dockerhost", this won't override it.
        """
        for node_name, data in self.topology.nodes(data=True):
            existing_t = data.get("type","unknown")
            # If already assigned "station" or "dockerhost", skip
            if existing_t not in ("host","switch","unknown"):
                continue

            # Otherwise, check name
            if node_name.startswith("ap"):
                data["type"] = "ap"
            elif node_name.startswith("sta"):
                data["type"] = "station"
            elif node_name.startswith("d"):
                data["type"] = "dockerhost"
            # If "sXX" => keep as switch
            elif existing_t == "switch":
                pass
            elif existing_t == "host":
                pass
            else:
                data["type"] = "unknown"

    def draw_topology(self):
        plt.figure(figsize=(8,6))
        pos = nx.spring_layout(self.topology, k=0.5, seed=42)

        # Collect nodes by type
        ap_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "ap"]
        station_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "station"]
        docker_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "dockerhost"]
        switch_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "switch"]
        host_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") in ("host","unknown")]

        # Draw sets of nodes with distinct color/shape
        nx.draw_networkx_nodes(
            self.topology, pos,
            nodelist=ap_nodes,
            node_color="orange",
            node_shape="p",
            node_size=700,
            label="Wi-Fi AP"
        )
        nx.draw_networkx_nodes(
            self.topology, pos,
            nodelist=station_nodes,
            node_color="violet",
            node_shape="D",
            node_size=600,
            label="Station"
        )
        nx.draw_networkx_nodes(
            self.topology, pos,
            nodelist=docker_nodes,
            node_color="yellow",
            node_shape="v",
            node_size=600,
            label="Docker Host"
        )
        nx.draw_networkx_nodes(
            self.topology, pos,
            nodelist=switch_nodes,
            node_color="skyblue",
            node_shape="s",
            node_size=600,
            label="Switches"
        )
        nx.draw_networkx_nodes(
            self.topology, pos,
            nodelist=host_nodes,
            node_color="lightgreen",
            node_shape="o",
            node_size=400,
            label="Hosts"
        )

        # Edges
        color_map = {"internal":"blue","external":"red"}
        edge_colors = []
        for u,v,edata in self.topology.edges(data=True):
            link_t = edata.get("link_type", "none")
            edge_colors.append(color_map.get(link_t, "gray"))

        nx.draw_networkx_edges(self.topology, pos, width=2, edge_color=edge_colors)
        nx.draw_networkx_labels(self.topology, pos, font_size=8, font_color="black")

        plt.title("Floodlight + Mininet-WiFi + Docker (DPID + IP Remap)")
        plt.axis("off")
        plt.legend()
        plt.show()

    def find_shortest_path(self, src_label, dst_label):
        if src_label not in self.topology:
            print(f"[Error] Source node {src_label} not in graph.")
            return None
        if dst_label not in self.topology:
            print(f"[Error] Destination node {dst_label} not in graph.")
            return None
        try:
            return nx.shortest_path(self.topology, src_label, dst_label)
        except nx.NetworkXNoPath:
            print(f"[Error] No path between {src_label} and {dst_label}")
            return None

# ------------------------------------------------------------------------------
# 3) FETCH WALLETS INFO (Similar to ganache_wallet_manager.py)
# ------------------------------------------------------------------------------
def fetch_wallet_info(floodlight_device_url="http://127.0.0.1:8080/wm/device/",
                      mnemonic="spend able critic rebuild flight mail trim brush vault solution juice jeans",
                      out_csv="wallets.csv"):
    """
      - We fetch the list of devices from Floodlight (so that we can map IP & MAC).
      - We derive wallet addresses & private keys for each device from a mnemonic.
      - Save results to a CSV file (wallets.csv).
    """
    try:
        r = requests.get(floodlight_device_url, timeout=5)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        info(f"[ERROR] Cannot fetch devices from {floodlight_device_url}: {e}\n")
        data = []

    if isinstance(data, dict) and "devices" in data:
        devices = data["devices"]
    elif isinstance(data, list):
        devices = data
    else:
        devices = []

    rows = []

    Account.enable_unaudited_hdwallet_features()
    hd_path = "m/44'/60'/0'/0/{}"

    def derive_wallet(idx):
        acct = Account.from_mnemonic(mnemonic, account_path=hd_path.format(idx))
        return acct.address, acct.key.hex()

    idx_counter = 0
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        aps = dev.get("attachmentPoint", [])
        if not aps:
            continue
        ap0 = aps[0]
        port = int(ap0.get("port", "1"))
        is_server = (port != 1)
        ipv4_list = dev.get("ipv4", [])
        if not ipv4_list:
            continue
        ip = ipv4_list[0]
        mac_list = dev.get("mac", [])
        if isinstance(mac_list, list) and mac_list:
            mac = mac_list[0]
        else:
            mac = "??"
        address, privkey = derive_wallet(idx_counter)
        idx_counter += 1

        rows.append({
            "mac": mac,
            "ip": ip,
            "is_server": is_server,
            "idx": idx_counter,
            "address": address,
            "privkey": privkey
        })

    if rows:
        with open(out_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["mac","ip","is_server","idx","address","privkey"])
            writer.writeheader()
            writer.writerows(rows)
        info(f"[+] Wrote {out_csv} with {len(rows)} rows\n")
    else:
        info("[WARNING] No hosts to write into wallets.csv\n")

# ------------------------------------------------------------------------------
# 4) TOKEN TRANSACTION FUNCTION (Similar to transfer_tokens.py)
# ------------------------------------------------------------------------------
def do_token_transfer(src_id, dst_id, amount,
                      wallets_csv="wallets.csv",
                      ganache_url="http://127.0.0.1:8545"):
    # 1. Read wallets.csv
    wallet_map = []
    if not os.path.exists(wallets_csv):
        info(f"[ERROR] {wallets_csv} not found. Please run fetch_wallet_info first.\n")
        return
    with open(wallets_csv, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            wallet_map.append(row)

    def find_wallet(identifier):
        # identifier might match IP or MAC
        for w in wallet_map:
            if w["ip"] == identifier or w["mac"] == identifier:
                return w
        return None

    src_wallet = find_wallet(src_id)
    dst_wallet = find_wallet(dst_id)

    if not src_wallet:
        info(f"[ERROR] No wallet found for src {src_id}\n")
        return
    if not dst_wallet:
        info(f"[ERROR] No wallet found for dst {dst_id}\n")
        return

    info(f"\n[INFO] Source wallet: {src_wallet}\n")
    info(f"[INFO] Destination wallet: {dst_wallet}\n")

    web3 = Web3(Web3.HTTPProvider(ganache_url))
    if not web3.is_connected():
        info("[ERROR] Cannot connect to Ganache.\n")
        return

    account_1 = src_wallet["address"]
    account_2 = dst_wallet["address"]
    private_key_1 = src_wallet["privkey"]

    amount_wei = web3.to_wei(amount, 'ether')

    nonce = web3.eth.get_transaction_count(account_1)

    tx = {
        'nonce': nonce,
        'to': account_2,
        'value': amount_wei,
        'gas': 2000000,
        'gasPrice': web3.to_wei('50', 'gwei'),
    }

    signed_tx = web3.eth.account.sign_transaction(tx, private_key_1)
    tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    tx_hash_hex = web3.to_hex(tx_hash)
    info(f"[INFO] Transaction sent, hash = {tx_hash_hex}\n")
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    info(f"[INFO] Transaction mined in block {receipt.blockNumber}\n")

# ------------------------------------------------------------------------------
# 5) FIND SHORTEST ROUTE FUNCTION
# ------------------------------------------------------------------------------
def find_shortest_route(net, src_ip, dst_ip):
    """
    Find the shortest path from src_ip to dst_ip using a simple BFS on
    an internal networkx graph. We assume each host/station in net
    has an IP that can be used to identify the node. We also assume
    the edges are unweighted for simplicity.
    Returns: list of node names from src_node to dst_node, or None if no path.
    """
    # Build a nodeName->IP dictionary
    # For stations, docker hosts, etc.
    node_ip_map = {}
    for node in net.hosts + net.stations + net.aps + net.switches:
        # Some nodes won't have IP (switches?), we skip or store dummy
        ip = getattr(node, 'IP', None)
        if ip:
            node_ip_map[node.name] = ip()

    # Identify which node is src, which node is dst
    src_node_name = None
    dst_node_name = None
    for n, ip_addr in node_ip_map.items():
        if ip_addr == src_ip:
            src_node_name = n
        if ip_addr == dst_ip:
            dst_node_name = n

    if not src_node_name:
        info(f"[ERROR] No node found with IP={src_ip}\n")
        return None
    if not dst_node_name:
        info(f"[ERROR] No node found with IP={dst_ip}\n")
        return None

    # Build a graph from net.links
    G = nx.Graph()
    # Add nodes
    all_nodes = set([sw.name for sw in net.switches] +
                    [ap.name for ap in net.aps] +
                    [h.name for h in net.hosts] +
                    [st.name for st in net.stations])
    for node_name in all_nodes:
        G.add_node(node_name)

    # Add edges
    for link in net.links:
        n1 = link.intf1.node.name
        n2 = link.intf2.node.name
        G.add_edge(n1, n2)

    try:
        # We'll find a path in the graph
        paths = nx.shortest_path(G, source=src_node_name, target=dst_node_name)
        return paths
    except nx.NetworkXNoPath:
        info("[ERROR] No path found.\n")
        return None

# ------------------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------------------
def main():
    setLogLevel('info')

    # 1) Create the custom topology
    net = create_custom_topology()
    # Start it
    net.start()

    # 2) Visualize
    fv = FloodlightVisualizer(
        # dpid_map=dpid_map,
        # docker_hosts_map=docker_hosts_map
    )
    fv.build_topology()
    fv.draw_topology()

    # 3) (Optional) Fetch wallets from Ganache / Floodlight device info
    #    If you want to rely on the actual Floodlight data, make sure
    #    your Floodlight is running, and you have devices discovered.
    fetch_wallet_info()

    # 4) Demonstrate a token transfer of 100 from one IP to another
    #    For example, if we have stations sta1 and sta2 with IPs 10.0.0.1, 10.0.0.2
    #    Adjust as needed.
    do_token_transfer("10.0.0.1", "10.0.0.2", 100)

    # 5) Shortest route example
    path = find_shortest_route(net, "10.0.0.1", "10.0.0.2")
    if path:
        info(f"[INFO] Shortest route from 10.0.0.1 to 10.0.0.2: {path}\n")

    # Let the user interact
    CLI(net)
    net.stop()

if __name__ == "__main__":
    main()
