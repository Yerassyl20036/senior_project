import requests
import networkx as nx
import matplotlib
matplotlib.use('TkAgg') 
import matplotlib.pyplot as plt

class FloodlightVisualizer:
    AP_MAP = {
        # "00:00:00:00:00:00:00:A1": "ap1",
        # "00:00:00:00:00:00:00:A2": "ap2",
        # etc.
    }

    def __init__(
        self,
        device_url="http://localhost:8080/wm/device/",
        links_url="http://localhost:8080/wm/topology/links/json"
    ):
        self.device_url = device_url
        self.links_url  = links_url
        self.topology   = nx.Graph()

    def fetch_json(self, url):
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

    def classify_node(self, label, is_switch=False):
        if is_switch:
            # If label includes "ap", we treat it as an Access Point
            if "ap" in label.lower():
                return "ap"
            else:
                return "switch"
        else:
            # It's a "host" from Floodlight's perspective. Let's see if it's a station or docker by name
            # e.g. "hsta1" => station, "hd1" => docker
            # If your naming is different, adjust accordingly
            if label.lower().startswith("hsta"):
                return "station"
            elif label.lower().startswith("hd"):
                return "docker"
            else:
                return "host"

    def add_switch_links(self):
        data = self.fetch_json(self.links_url)
        if not data or not isinstance(data, list):
            print("[Warning] /wm/topology/links/json did not return a list. No switch links added.")
            return

        for link in data:
            src_dpid = link.get("src-switch", "")
            dst_dpid = link.get("dst-switch", "")
            if not src_dpid or not dst_dpid:
                continue

            # Rename if in AP_MAP
            src_label = self.AP_MAP.get(src_dpid, f"s{src_dpid}")
            dst_label = self.AP_MAP.get(dst_dpid, f"s{dst_dpid}")

            # Then classify
            src_type = self.classify_node(src_label, is_switch=True)
            dst_type = self.classify_node(dst_label, is_switch=True)

            self.topology.add_node(src_label, type=src_type)
            self.topology.add_node(dst_label, type=dst_type)

            # Add the edge
            self.topology.add_edge(
                src_label,
                dst_label,
                src_port=link.get("src-port"),
                dst_port=link.get("dst-port"),
                link_type=link.get("type"),
                direction=link.get("direction")
            )

    def add_hosts(self):
        data = self.fetch_json(self.device_url)
        if not data:
            print("[Warning] /wm/device/ returned no data. No hosts added.")
            return

        if isinstance(data, dict) and "devices" in data:
            devices = data["devices"]
        elif isinstance(data, list):
            devices = data
        else:
            print("[Warning] /wm/device/ had an unexpected JSON shape. No hosts added.")
            return

        for dev in devices:
            if not isinstance(dev, dict):
                continue

            mac_str = dev.get("mac", "")
            ipv4_list = dev.get("ipv4", [])
            ap_list = dev.get("attachmentPoint", [])

            if not ap_list or not isinstance(ap_list, list):
                continue

            # We'll take the first attachmentPoint
            ap = ap_list[0]
            switch_dpid = ap.get("switch") or ap.get("switchDPID")
            port = ap.get("port")
            if not switch_dpid or port is None:
                continue

            # Construct host label: h{ipv4} or h{mac}
            if ipv4_list:
                host_label = f"h{ipv4_list[0]}"
            else:
                # fallback to MAC if no IPv4
                if isinstance(mac_str, list) and len(mac_str) > 0:
                    mac_str = mac_str[0]
                host_label = f"h{mac_str}"

            if not host_label:
                continue

            # Classify the "host" type
            host_type = self.classify_node(host_label, is_switch=False)
            self.topology.add_node(host_label, type=host_type)

            # The switch label
            sw_label = self.AP_MAP.get(switch_dpid, f"s{switch_dpid}")  # rename if it's an AP
            if sw_label not in self.topology:
                sw_type = self.classify_node(sw_label, is_switch=True)
                self.topology.add_node(sw_label, type=sw_type)

            # Add edge host->switch
            self.topology.add_edge(
                host_label,
                sw_label,
                port=port
            )

    def build_topology(self):
        self.add_switch_links()
        self.add_hosts()

    def draw_topology(self):
        plt.figure(figsize=(8,6))

        pos = nx.spring_layout(self.topology, k=0.5, seed=42)

        switch_nodes  = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "switch"]
        ap_nodes      = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "ap"]
        host_nodes    = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "host"]
        station_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "station"]
        docker_nodes  = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "docker"]

        # Switches
        nx.draw_networkx_nodes(
            self.topology,
            pos,
            nodelist=switch_nodes,
            node_color="skyblue",
            node_shape="s",
            node_size=600,
            label="Switches"
        )
        # APs
        nx.draw_networkx_nodes(
            self.topology,
            pos,
            nodelist=ap_nodes,
            node_color="orange",
            node_shape="s",
            node_size=600,
            label="Wi-Fi APs"
        )
        # Basic hosts
        nx.draw_networkx_nodes(
            self.topology,
            pos,
            nodelist=host_nodes,
            node_color="lightgreen",
            node_shape="o",
            node_size=400,
            label="Hosts"
        )
        # Stations
        nx.draw_networkx_nodes(
            self.topology,
            pos,
            nodelist=station_nodes,
            node_color="violet",
            node_shape="o",
            node_size=400,
            label="Stations"
        )
        # Docker hosts
        nx.draw_networkx_nodes(
            self.topology,
            pos,
            nodelist=docker_nodes,
            node_color="pink",
            node_shape="o",
            node_size=400,
            label="Docker"
        )

        # Draw edges
        nx.draw_networkx_edges(self.topology, pos, width=1.5, edge_color="gray")

        # Label nodes
        nx.draw_networkx_labels(self.topology, pos, font_size=8, font_color="black")

        plt.title("Floodlight Network Topology (AP + Wi-Fi + Docker + Switches)")
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
            return nx.shortest_path(self.topology, source=src_label, target=dst_label)
        except nx.NetworkXNoPath:
            print(f"[Error] No path between {src_label} and {dst_label}")
            return None


if __name__ == "__main__":
    # Example usage
    fv = FloodlightVisualizer()

    fv.build_topology()

    path = fv.find_shortest_path("h10.0.0.1", "h10.0.0.3")
    if path:
        print("Shortest path from h10.0.0.1 to h10.0.0.3:", path)

    fv.draw_topology()
