import os
import random
import requests
import matplotlib
import networkx as nx
from web3 import Web3
from mininet.log import info
import csv, datetime, pathlib
import matplotlib.pyplot as plt
from eth_account import Account
matplotlib.use('TkAgg')

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

            # -- inside add_switch_links() ---------------------------------
            src_label = self.remap_dpid(src_dpid)
            dst_label = self.remap_dpid(dst_dpid)

            src_kind = "ap"      if str(src_dpid).startswith("1") else "switch"
            dst_kind = "ap"      if str(dst_dpid).startswith("1") else "switch"

            self.topology.add_node(src_label, type=src_kind, dpid=src_dpid)
            self.topology.add_node(dst_label, type=dst_kind, dpid=dst_dpid)

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

    def add_hosts(self):
        data = self.fetch_json(self.device_url)
        if not data:
            print("[Warning] /wm/device/ returned no data.")
            return

        devices = data["devices"] if isinstance(data, dict) and "devices" in data else data
        if not isinstance(devices, list):
            print("[Warning] /wm/device/ had unexpected JSON shape.")
            return

        for dev in devices:
            if not isinstance(dev, dict):
                continue

            aps = dev.get("attachmentPoint", [])
            if not aps:
                continue
            ap0       = aps[0]
            port      = int(ap0.get("port", "1"))      # default to 1
            is_server = (port != 1)                    # ** OUR RULE **

            mac_list  = dev.get("mac", [])
            if isinstance(mac_list, str):
                mac_list = [mac_list]
            mac = mac_list[0].lower() if mac_list else ""

            ipv4_list = dev.get("ipv4", [])
            ip  = ipv4_list[0] if ipv4_list else None

            # Decide a label for the host (as before)
            if ip and ip in self.docker_hosts_map:
                host_label = self.docker_hosts_map[ip]
                host_type  = "dockerhost"
            else:
                host_label = f"h{ip or mac.replace(':','')}"
                host_type  = "host"

            # Add the host vertex, **embedding the flag & MAC/IP**
            self.topology.add_node(
                host_label,
                type=host_type,
                mac=mac,
                ip=ip,
                is_server=is_server
            )

            # Link host → switch
            sw_dpid = ap0.get("switch") or ap0.get("switchDPID")
            if not sw_dpid:
                continue
            sw_label  = self.remap_dpid(sw_dpid)
            sw_kind   = "ap" if str(sw_dpid).startswith("1") else "switch"
            self.topology.add_node(sw_label, type=sw_kind, dpid=sw_dpid)
            self.topology.add_edge(host_label, sw_label, port=port)

    def classify_nodes(self):
        for node_name, data in self.topology.nodes(data=True):
            current = data.get("type", "unknown")

            if current in ("ap", "station", "dockerhost", "switch"):
                continue

            if data.get("is_server") is True:
                data["type"] = "dockerhost"
                continue
            elif data.get("is_server") is False:
                data["type"] = "host"
                continue

            if node_name.startswith("ap"):
                data["type"] = "ap"
            elif node_name.startswith("sta"):
                data["type"] = "station"
            elif node_name.startswith("d"):
                data["type"] = "dockerhost"
            elif current == "host" or current == "unknown":
                data["type"] = "station"
            # leave switches untouched

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
        
    # def simulate_request(self, src_ip):
    #     ip_to_node = {}
    #     docker_nodes = []
    #     for n, d in self.topology.nodes(data=True):
    #         ip_attr = d.get("ip")
    #         if ip_attr:
    #             ip_to_node[ip_attr] = n
    #         if d.get("type") == "dockerhost":
    #             docker_nodes.append(n)
    
    #     if src_ip not in ip_to_node:
    #         print(f"[Error] No node in the graph has IP {src_ip}")
    #         return None, None, None
    #     if not docker_nodes:
    #         print("[Error] No docker hosts present in the topology.")
    #         return None, None, None
    
    #     src_node = ip_to_node[src_ip]
    
    #     best_path = None
    #     best_len  = float("inf")
    #     best_docker_node = None
    
    #     for dnode in docker_nodes:
    #         try:
    #             p = nx.shortest_path(self.topology, src_node, dnode)
    #         except nx.NetworkXNoPath:
    #             continue
    #         if len(p) < best_len:           # strictly shorter
    #             best_len = len(p)
    #             best_path = p
    #             best_docker_node = dnode
    
    #     if best_path is None:
    #         print(f"[Error] No path from {src_ip} to any docker host.")
    #         return None, None, None
    
    #     docker_ip = self.topology.nodes[best_docker_node].get("ip")
    #     hop_cost  = (len(best_path) - 1 ) * 10         # edges, not vertices
    #     return docker_ip, best_path, hop_cost
    
    def simulate_request(self, src_ip):
        ip_to_node = {}
        docker_nodes = []
        for n, d in self.topology.nodes(data=True):
            ip_attr = d.get("ip")
            if ip_attr:
                ip_to_node[ip_attr] = n
            if d.get("type") == "dockerhost":
                docker_nodes.append(n)
    
        if src_ip not in ip_to_node:
            print(f"[Error] No node in the graph has IP {src_ip}")
            return None, None, None
        if not docker_nodes:
            print("[Error] No docker hosts present in the topology.")
            return None, None, None
    
        src_node = ip_to_node[src_ip]
    
        best_path = None
        best_len = None
        candidates = []          # docker nodes that are equally‐near

        for dnode in docker_nodes:
            try:
                p = nx.shortest_path(self.topology, src_node, dnode)
            except nx.NetworkXNoPath:
                continue
            L = len(p)
            if best_len is None or L < best_len:
                best_len = L
                candidates = [(dnode, p)]
            elif L == best_len:
                candidates.append((dnode, p))

        if not candidates:
            print(f"[Error] No path from {src_ip} to any docker host.")
            return None, None, None

        dnode, best_path = random.choice(candidates)   # <- NEW
        docker_ip = self.topology.nodes[dnode]["ip"]
        hop_cost  = (len(best_path) - 1) * 10
        return docker_ip, best_path, hop_cost
        
class TxLogger:
    def __init__(self, logfile="tx_log.csv"):
        self.path = pathlib.Path(logfile)
        if not self.path.exists():
            with self.path.open("w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "event_id", 
                    "ts","src_ip","dst_ip",
                    "hop_cost","req_cost","total_eth",
                    "src_bal_before","src_bal_after",
                    "dst_bal_before","dst_bal_after",
                    "tx_hash"
                ])

    def write(self, row):
        with self.path.open("a", newline="") as f:
            csv.writer(f).writerow(row)

#   IMPORTANT UPDATE MNEMONIC EACH TIME WHEN NEW GANACHE INSTANCE IS LAUCHED
def fetch_wallet_info(floodlight_device_url="http://127.0.0.1:8080/wm/device/",
                      mnemonic="quantum crack attitude guess stand tide crazy onion fabric plug wet enforce",
                      out_csv="wallets.csv"):
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

def do_token_transfer(src_id, dst_id,
                      hop_cost, req_cost,
                      wallets_csv="wallets.csv",
                      ganache_url="http://127.0.0.1:8545",
                      logger=None, cycle = 0):         
    
    total_eth = hop_cost + req_cost

    if not os.path.exists(wallets_csv):
        info("[ERROR] wallets.csv missing\n")
        return False, ""

    with open(wallets_csv, newline="") as f:
        wallets = list(csv.DictReader(f))

    def w_by_ip(ip):
        for w in wallets:
            if w["ip"] == ip:
                return w
        return None

    src_w, dst_w = w_by_ip(src_id), w_by_ip(dst_id)
    if not src_w or not dst_w:
        info("[WARN] wallet not found (src=%s dst=%s)\n" % (src_id, dst_id))
        return False, ""

    w3 = Web3(Web3.HTTPProvider(ganache_url))
    if not w3.is_connected():   
        info("[ERROR] Ganache offline\n")
        return False, ""

    bal_src_before = float(w3.from_wei(w3.eth.get_balance(src_w["address"]), "ether"))
    bal_dst_before = float(w3.from_wei(w3.eth.get_balance(dst_w["address"]), "ether"))

    if bal_src_before < total_eth:
        info(f"[SKIP] {src_id} lacks funds ({bal_src_before} < {total_eth})\n")
        if logger:
            logger.write([
                cycle,
                datetime.datetime.utcnow().isoformat(),
                src_id, dst_id,
                hop_cost, req_cost, total_eth,
                bal_src_before, bal_src_before,
                bal_dst_before, bal_dst_before,
                ""
            ])
        return False, ""

    tx = {
        "nonce": w3.eth.get_transaction_count(src_w["address"]),
        "to":    dst_w["address"],
        "value": w3.to_wei(total_eth, "ether"),
        "gas":   21000,
        "gasPrice": w3.to_wei("1", "gwei"),
    }
    signed = w3.eth.account.sign_transaction(tx, src_w["privkey"])
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    w3.eth.wait_for_transaction_receipt(tx_hash)

    bal_src_after = float(w3.from_wei(w3.eth.get_balance(src_w["address"]), "ether"))
    bal_dst_after = float(w3.from_wei(w3.eth.get_balance(dst_w["address"]), "ether"))

    info(f"[TX] {src_id}→{dst_id}  {total_eth} ETH  hash={w3.to_hex(tx_hash)}\n")

    if logger:
        logger.write([
            cycle,
            datetime.datetime.utcnow().isoformat(),
            src_id, dst_id,
            hop_cost, req_cost, total_eth,
            bal_src_before, bal_src_after,
            bal_dst_before, bal_dst_after,
            w3.to_hex(tx_hash)
        ])
    return True, w3.to_hex(tx_hash)

def find_shortest_route(net, src_ip, dst_ip):
    node_ip_map = {}
    for node in net.hosts + net.stations + net.aps + net.switches:
        ip = getattr(node, 'IP', None)
        if ip:
            node_ip_map[node.name] = ip()

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

    G = nx.Graph()
    all_nodes = set([sw.name for sw in net.switches] +
                    [ap.name for ap in net.aps] +
                    [h.name for h in net.hosts] +
                    [st.name for st in net.stations])
    for node_name in all_nodes:
        G.add_node(node_name)

    for link in net.links:
        n1 = link.intf1.node.name
        n2 = link.intf2.node.name
        G.add_edge(n1, n2)

    try:
        paths = nx.shortest_path(G, source=src_node_name, target=dst_node_name)
        return paths
    except nx.NetworkXNoPath:
        info("[ERROR] No path found.\n")
        return None
    
def run_bulk_simulation(fv,
                        req_min=1, req_max=100,
                        wallets_csv="wallets.csv"):
    host_ips = []
    for n, d in fv.topology.nodes(data=True):
        if d.get("type") in ("host", "station"):
            if d.get("ip"):
                host_ips.append(d["ip"])
    print(f"Found {len(host_ips)} host IPs in the topology.")
    
    random.shuffle(host_ips)

    for ip in host_ips:
        docker_ip, path, hop_cost = fv.simulate_request(ip)
        if not docker_ip:
            continue

        req_cost = random.randint(req_min, req_max)   # ETH
        success  = do_token_transfer(ip, docker_ip,
                                     hop_cost, req_cost,
                                     wallets_csv=wallets_csv)
        if success:
            info(f"[OK ] {ip} paid {hop_cost}+{req_cost} ETH "
                 f"to {docker_ip}  via {len(path)-1} hops\n")
            
def _wallet_by_ip(ip, wallets, w3):
    for row in wallets:
        if row["ip"] == ip:
            bal = w3.from_wei(w3.eth.get_balance(row["address"]), "ether")
            return row, float(bal)
    return None, 0.0

def run_bulk_simulation_loop(fv,
                             req_min=1, req_max=100,
                             wallets_csv="wallets.csv",
                             ganache_url="http://127.0.0.1:8545",
                             logger=None):
    
    if logger is None:
        info("[ERROR] run_bulk_simulation_loop needs a TxLogger instance\n")
        return
    
    # load wallets once
    if not os.path.exists(wallets_csv):
        info("[ERROR] wallets.csv not found.\n")
        return
    with open(wallets_csv, newline="") as f:
        wallets = list(csv.DictReader(f))

    w3 = Web3(Web3.HTTPProvider(ganache_url))
    if not w3.is_connected():
        info("[ERROR] cannot reach Ganache RPC.\n")
        return

    # gather ordinary‑host IPs
    host_ips = [d["ip"] for n, d in fv.topology.nodes(data=True)
                if d.get("type") in ("host", "station") and d.get("ip")]

    cycle = 0
    while True:
        cycle += 1
        any_tx = False

        random.shuffle(host_ips)
        for ip in host_ips:
            wallet, bal = _wallet_by_ip(ip, wallets, w3)
            if bal <= 0:
                continue   # broke

            docker_ip, path, hop_cost = fv.simulate_request(ip)
            if not docker_ip:
                continue

            # choose request cost, but cap to available balance
            max_affordable = max(0, int(bal - hop_cost))
            if max_affordable == 0:
                continue

            req_cost = random.randint(req_min, min(req_max, max_affordable))
            ok = do_token_transfer(ip, docker_ip,
                       hop_cost, req_cost,
                       wallets_csv=wallets_csv,
                       ganache_url=ganache_url,
                       logger=logger,
                       cycle = cycle)          
            if ok:
                any_tx = True

        # stop when no transfer succeeded in this sweep
        if not any_tx:
            info(f"[DONE] all ordinary hosts are out of funds after {cycle} cycles.\n")
            break


if __name__ == "__main__":
    fv = FloodlightVisualizer(
    )
    fv.build_topology()
    # fv.draw_topology()
    fetch_wallet_info()
    # docker_ip, path, cost = fv.simulate_request("10.0.0.1")
    # if docker_ip:
    #     print("Nearest docker host:", docker_ip)
    #     print("Path :", " → ".join(path))
    #     print("Cost :", cost, "hops")

    #     do_token_transfer("10.0.0.1", docker_ip, cost)
    logger = TxLogger("tx_log.csv")   # initialise CSV log
    run_bulk_simulation_loop(fv, logger=logger)