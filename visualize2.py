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
        dpid_map=None
    ):
        """
        dpid_map: optional dict mapping dpids -> custom names
                  e.g. {"00:00:00:00:00:00:00:05": "ap1"}
        """
        self.device_url = device_url
        self.links_url  = links_url

        self.topology   = nx.Graph()
        self.dpid_map   = dpid_map or {}

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

    def remap_dpid(self, dpid_str):
        """
        If dpid_str in self.dpid_map, return that custom name,
        else build default "s{dpid}".
        """
        if dpid_str in self.dpid_map:
            return self.dpid_map[dpid_str]
        else:
            return f"s{dpid_str}"

    def add_switch_links(self):
        data = self.fetch_json(self.links_url)
        if not data or not isinstance(data, list):
            print("[Warning] /wm/topology/links/json did not return a list.")
            return

        for link in data:
            src_dpid = link.get("src-switch", "")
            dst_dpid = link.get("dst-switch", "")
            if not src_dpid or not dst_dpid:
                continue

            # **Remap** using self.remap_dpid
            src_label = self.remap_dpid(src_dpid)
            dst_label = self.remap_dpid(dst_dpid)

            self.topology.add_node(src_label, type="switch")
            self.topology.add_node(dst_label, type="switch")

            link_type = link.get("type", "")
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
            print("[Warning] Unexpected JSON shape from /wm/device/.")
            return

        for dev in devices:
            if not isinstance(dev, dict):
                continue

            mac_str = dev.get("mac", "")
            ipv4_list = dev.get("ipv4", [])
            ap_list = dev.get("attachmentPoint", [])
            if not ap_list or not isinstance(ap_list, list):
                continue

            ap = ap_list[0]
            switch_dpid = ap.get("switch") or ap.get("switchDPID")
            port = ap.get("port")
            if not switch_dpid or port is None:
                continue

            # Build host label
            if ipv4_list:
                host_label = f"h{ipv4_list[0]}"
            else:
                if isinstance(mac_str, list) and len(mac_str) > 0:
                    mac_str = mac_str[0]
                host_label = f"h{mac_str}"

            self.topology.add_node(host_label, type="host")

            # Remap switch dpid
            switch_label = self.remap_dpid(switch_dpid)
            self.topology.add_node(switch_label, type="switch")

            self.topology.add_edge(
                host_label,
                switch_label,
                port=port
            )

    def build_topology(self):
        self.add_switch_links()
        self.add_hosts()
        self.classify_nodes()

    def classify_nodes(self):
        for node_name, data in self.topology.nodes(data=True):
            # If the node_name starts with "ap", treat it as an AP
            if node_name.startswith("ap"):
                data["type"] = "ap"
            elif node_name.startswith("sta"):
                data["type"] = "station"
            elif node_name.startswith("d"):
                data["type"] = "dockerhost"
            elif data.get("type") == "switch" and node_name.startswith("s"):
                # keep type switch
                pass
            elif data.get("type") == "host":
                pass
            else:
                data.setdefault("type", "unknown")

    def draw_topology(self):
        plt.figure(figsize=(8,6))
        pos = nx.spring_layout(self.topology, k=0.5, seed=42)

        ap_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "ap"]
        station_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "station"]
        docker_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "dockerhost"]
        switch_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "switch"]
        host_nodes = [n for n,d in self.topology.nodes(data=True) if d.get("type") == "host" or d.get("type") == "unknown"]

        nx.draw_networkx_nodes(pos=pos, G=self.topology,
            nodelist=ap_nodes,
            node_color="orange", node_shape="p", node_size=700, label="Wi-Fi AP"
        )
        nx.draw_networkx_nodes(pos=pos, G=self.topology,
            nodelist=station_nodes,
            node_color="violet", node_shape="D", node_size=600, label="Station"
        )
        nx.draw_networkx_nodes(pos=pos, G=self.topology,
            nodelist=docker_nodes,
            node_color="yellow", node_shape="v", node_size=600, label="Docker Host"
        )
        nx.draw_networkx_nodes(pos=pos, G=self.topology,
            nodelist=switch_nodes,
            node_color="skyblue", node_shape="s", node_size=600, label="Switches"
        )
        nx.draw_networkx_nodes(pos=pos, G=self.topology,
            nodelist=host_nodes,
            node_color="lightgreen", node_shape="o", node_size=400, label="Hosts"
        )

        color_map = { "internal": "blue", "external": "red" }
        edge_colors = []
        for u,v,edata in self.topology.edges(data=True):
            link_t = edata.get("link_type", "none")
            edge_colors.append(color_map.get(link_t, "gray"))

        nx.draw_networkx_edges(self.topology, pos, width=2, edge_color=edge_colors)
        nx.draw_networkx_labels(self.topology, pos, font_size=8, font_color="black")

        plt.title("Floodlight + Mininet-WiFi + Docker (DPID Remap)")
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


if __name__ == "__main__":
    # Suppose from the custom_topo logs we found:
    # ap1 name=ap1, dpid=00:00:00:00:00:00:00:05
    # ap2 name=ap2, dpid=00:00:00:00:00:00:00:09
    # We map them here:
    dpid_map = {
    "10:00:00:00:00:00:00:01": "ap1",
    "10:00:00:00:00:00:00:02": "ap2"
    }


    fv = FloodlightVisualizer(dpid_map=dpid_map)
    fv.build_topology()

    # Now we can do find_shortest_path("ap1","sta3") etc.
    path = fv.find_shortest_path("ap1", "sta2")
    if path:
        print("Path from ap1 to sta2:", path)

    fv.draw_topology()
