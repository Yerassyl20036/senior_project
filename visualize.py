#!/usr/bin/env python3
import requests
import networkx as nx
import matplotlib
matplotlib.use('TkAgg')  # so it doesn't cause crash in ubuntu 22.04 gnome etc.
import matplotlib.pyplot as plt

class FloodlightVisualizer:
    def __init__(
        self,
        device_url="http://localhost:8080/wm/device/",
        links_url="http://localhost:8080/wm/topology/links/json"
    ):
        self.device_url = device_url
        self.links_url  = links_url

        # We'll store a single undirected graph
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

        # Attempt JSON decode
        try:
            return resp.json()
        except ValueError as e:
            print("[Error] Could not parse JSON:", e)
            print("Response text:", resp.text)
            return None

    def add_switch_links(self):
        data = self.fetch_json(self.links_url)
        if not data or not isinstance(data, list):
            print("[Warning] /wm/topology/links/json did not return a list. No switch links added.")
            return

        for link in data:
            # link should have 'src-switch', 'dst-switch', 'src-port', 'dst-port'
            src_dpid = link.get("src-switch", "")
            dst_dpid = link.get("dst-switch", "")

            if not src_dpid or not dst_dpid:
                # Skip invalid entries
                continue

            src_label = f"s{src_dpid}"
            dst_label = f"s{dst_dpid}"

            # Add nodes to the graph (NetworkX will ignore duplicates)
            self.topology.add_node(src_label, type="switch")
            self.topology.add_node(dst_label, type="switch")

            # Attempt to parse link_type
            link_type = link.get("type", "")  # e.g. "internal" or "external"
            direction = link.get("direction", "")  # "bidirectional"?

            # Add an edge for the link
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
            print("[Warning] /wm/device/ returned no data. No hosts added.")
            return

        # Some Floodlight versions respond with a list of devices or { "devices": [...] }
        if isinstance(data, dict) and "devices" in data:
            devices = data["devices"]
        elif isinstance(data, list):
            devices = data
        else:
            print("[Warning] /wm/device/ had an unexpected JSON shape. No hosts added.")
            return

        for dev in devices:
            # e.g. { "mac":"00:11:22:33:44:55",
            #        "ipv4":["10.0.0.1"],
            #        "attachmentPoint":[{"switchDPID":"00:00:00:00:00:00:00:01","port":1}] }
            if not isinstance(dev, dict):
                continue
            
            mac_str = dev.get("mac", "")
            ipv4_list = dev.get("ipv4", [])

            # Must have an attachmentPoint
            ap_list = dev.get("attachmentPoint", [])
            if not ap_list or not isinstance(ap_list, list):
                continue
            
            ap = ap_list[0]
            switch_dpid = ap.get("switch") or ap.get("switchDPID")
            port = ap.get("port")

            if not switch_dpid or port is None:
                continue

            # Build the host label
            if ipv4_list:
                host_label = f"h{ipv4_list[0]}"
            else:
                # fallback to "hMAC"
                if isinstance(mac_str, list) and len(mac_str) > 0:
                    mac_str = mac_str[0]
                host_label = f"h{mac_str}"

            if not host_label:
                continue

            # Add the host
            self.topology.add_node(host_label, type="host")

            # The switch label
            switch_label = f"s{switch_dpid}"
            self.topology.add_node(switch_label, type="switch")

            # Add edge host->switch
            self.topology.add_edge(
                host_label,
                switch_label,
                port=port
            )

    def build_topology(self):
        self.add_switch_links()
        self.add_hosts()

        # Optionally classify APs, Docker, stations, etc. from names:
        self.classify_nodes()

    def classify_nodes(self):
        for node_name, data in self.topology.nodes(data=True):
            # If we already have a 'type' that says "switch" or "host", keep it
            # But we can refine if the name suggests it's an AP or station
            # or Docker host
            node_type = data.get("type", "unknown")

            # If it's "switch" but name starts with 'ap', call it an AP
            if node_name.startswith('ap'):
                data["type"] = "ap"
            elif node_name.startswith('sta'):
                data["type"] = "station"
            elif node_name.startswith('d'):
                data["type"] = "dockerhost"
            # If it's e.g. "s1" or "s00:00:...", keep it as "switch"
            # If it's e.g. "h10.0.0.1", keep it as "host" unless we see a reason not to
            # If it doesn't match anything, we let the existing or "host" stand.
            # else:
            #     # keep the existing data["type"]
            #     pass

    def draw_topology(self):
        plt.figure(figsize=(8,6))

        # A layout
        pos = nx.spring_layout(self.topology, k=0.5, seed=42)

        # We'll create sub-lists by type
        ap_nodes     = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "ap"]
        station_nodes= [n for n,d in self.topology.nodes(data=True) if d.get("type") == "station"]
        docker_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "dockerhost"]
        switch_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "switch"]
        host_nodes   = [n for n,d in self.topology.nodes(data=True)
                        if d.get("type") == "host" or d.get("type") == "unknown"]

        # Draw APs as pentagon (p), orange
        nx.draw_networkx_nodes(
            self.topology,
            pos,
            nodelist=ap_nodes,
            node_color="orange",
            node_shape="p",
            node_size=700,
            label="Wi-Fi AP"
        )

        # Draw stations as diamond (D), purple
        nx.draw_networkx_nodes(
            self.topology,
            pos,
            nodelist=station_nodes,
            node_color="violet",
            node_shape="D",
            node_size=600,
            label="Station"
        )

        # Draw docker hosts as triangle (v), yellow
        nx.draw_networkx_nodes(
            self.topology,
            pos,
            nodelist=docker_nodes,
            node_color="yellow",
            node_shape="v",
            node_size=600,
            label="Docker Host"
        )

        # Draw switches as squares (s), skyblue
        nx.draw_networkx_nodes(
            self.topology,
            pos,
            nodelist=switch_nodes,
            node_color="skyblue",
            node_shape="s",
            node_size=600,
            label="Switches"
        )

        # Draw normal hosts as circles (o), lightgreen
        nx.draw_networkx_nodes(
            self.topology,
            pos,
            nodelist=host_nodes,
            node_color="lightgreen",
            node_shape="o",
            node_size=400,
            label="Hosts"
        )

        # We also color edges differently if they are e.g. "internal" vs "external"
        # If "type" is not present, default gray
        color_map = {
            "internal": "blue",
            "external": "red",
            # default => "gray"
        }
        edge_colors = []
        for u,v,edata in self.topology.edges(data=True):
            link_t = edata.get("link_type", "none")
            edge_colors.append(color_map.get(link_t, "gray"))

        nx.draw_networkx_edges(
            self.topology, pos, width=2, edge_color=edge_colors
        )

        # Label them
        nx.draw_networkx_labels(self.topology, pos, font_size=8, font_color="black")

        plt.title("Floodlight + Mininet-WiFi + Docker Topology")
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
            path = nx.shortest_path(self.topology, source=src_label, target=dst_label)
            return path
        except nx.NetworkXNoPath:
            print(f"[Error] No path between {src_label} and {dst_label}")
            return None


if __name__ == "__main__":
    fv = FloodlightVisualizer()
    fv.build_topology()

    # Example: find shortest path between two host IP nodes
    # e.g. "h10.0.0.1" or "ap1", "sta2", etc.
    path = fv.find_shortest_path("ap1", "sta2")
    if path:
        print("Shortest path from ap1 to sta2:", path)

    # Visualize it
    fv.draw_topology()
