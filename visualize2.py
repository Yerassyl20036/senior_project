#!/usr/bin/env python3
import requests
import networkx as nx
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt

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

# EXAMPLE USAGE
if __name__ == "__main__":
    """
    Example scenario:
    - Suppose from custom_topo, we got:
      ap1 => dpid=1000000000000001
      ap2 => dpid=1000000000000002
    - We know station IPs: 10.0.0.2 => "sta2"
    - We know Docker host IP: 10.0.0.4 => "d1"
    """
    dpid_map = {
    "10:00:00:00:00:00:00:01": "ap1",
    "10:00:00:00:00:00:00:02": "ap2"
    }
    
    docker_hosts_map = {
        "10.0.0.4": "d1"
    }

    fv = FloodlightVisualizer(
        dpid_map=dpid_map,
        docker_hosts_map=docker_hosts_map
    )
    fv.build_topology()

    # Now we can do find_shortest_path("ap1", "sta2"), for example
    path = fv.find_shortest_path("ap1", "sta2")
    if path:
        print("Path from ap1 to sta2:", path)

    fv.draw_topology()