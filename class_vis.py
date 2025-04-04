import requests
import networkx as nx
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('TkAgg')  # so it doesn't cause crash in ubuntu 22.04 gnome etc.
import matplotlib.pyplot as mplt


class Visualizer:
    def __init__(self, device_u = 'http://localhost:8080/wm/device/', links_u = 'http://localhost:8080/wm/topology/links/json') -> None:
        self.device_url = device_u
        self.links_url = links_u

        self.topology = nx.Graph()
        self.hosts = []
        self.switches = []
        self.controller = []
        self.switches_hosts = {}
        self.switches_switches = {}

    @staticmethod
    def read_json(json_url) -> pd.DataFrame:
        return pd.read_json(json_url)
    
    def add_switches(self) -> None:
        switches_df = self.read_json(self.links_url)
        
        for index, connection in switches_df.iterrows():
            src_switch = f"s{connection['src-switch']}"
            dst_switch = f"s{connection['dst-switch']}"

            if src_switch not in self.switches_switches:
                self.switches_switches[src_switch] = []
            if dst_switch not in self.switches_switches:
                self.switches_switches[dst_switch] = []    

            self.switches_switches[src_switch].append((dst_switch, connection['src-port']))
            self.switches_switches[dst_switch].append((src_switch, connection['dst-port']))
            self.switches_hosts[src_switch] = []
            self.switches_hosts[dst_switch] = []    
        
            self.topology.add_edge(src_switch, dst_switch)
        
        print(self.switches_hosts, '\n')
        print(self.switches_switches, '\n')

    def add_hosts(self) -> None:
        hosts_df = self.read_json(self.device_url)
        hosts_df = hosts_df['devices']

        for host in hosts_df:
            if host['ipv4']:
                self.hosts.append(host)
                switch = f"s{host['attachmentPoint'][0]['switch']}"
                port = f"{host['attachmentPoint'][0]['port']}"
                host_ip = f"h{host['ipv4'][0]}"
                self.switches_hosts[switch].append((host_ip, port))
                self.topology.add_edge(switch, host_ip)


        print(self.switches_hosts)

    def plot_graph(self) -> None:
        pos = nx.spring_layout(self.topology)
        nx.draw(self.topology, pos, with_labels=True,node_size=700,node_color='skyblue')
        node_labels = nx.get_node_attributes(self.topology,'type')
        nx.draw_networkx_labels(self.topology,pos)#, labels=node_labels)     

        mplt.show() 

    def find_shortest_path(self, src_host, dst_host) -> list:
        try:
            return list(nx.all_shortest_paths(self.topology, source=src_host, target=dst_host))
        except nx.NetworkXNoPath:
            return []
 
    #def find_connection_port(self)

    def compute_path_cost(self, bandwidth_urls) -> int:
        path_cost = 0
        for bandwidth_url in bandwidth_urls:
            port_info = self.read_json(bandwidth_url)
            rx = int(port_info['bits-per-second-rx'].values[0])
            tx = int(port_info['bits-per-second-tx'].values[0])
            path_cost += abs(rx-tx)
            return path_cost
        

    def find_optimal_path(self, src_host, dst_host) -> list:
        shortest_paths = self.find_shortest_path(src_host, dst_host)
        bandwidth_urls = []
        if not shortest_paths:
            return ["NO OPTIMAL PATH"]

        optimal_path = []
        path_cost = 1
        for path in shortest_paths:
            switches_in_path = path[1:-1]
            for i in range(len(switches_in_path) - 1):
                src_switch = switches_in_path[i]
                dst_switch = switches_in_path[i+1]


                for (connected_switch, port) in self.switches_switches[src_switch]:
                    if connected_switch == dst_switch:
                        bandwidth_urls.append(f"http://localhost:8080/wm/statistics/bandwidth/{src_switch[1:]}/{port}/json")
            print(bandwidth_urls, "\n")
            local_path_cost = self.compute_path_cost(bandwidth_urls)
            if local_path_cost < path_cost:
                path_cost = local_path_cost
                optimal_path = path
            print(self.compute_path_cost(bandwidth_urls))
            bandwidth_urls = []
        return optimal_path

visualizer = Visualizer()
visualizer.add_switches() 
visualizer.add_hosts() 
print("Shortest path: ", visualizer.find_shortest_path("h10.0.0.1", "h10.0.0.4"), "\n")   
print("The most optimal path: ",visualizer.find_optimal_path("h10.0.0.1", "h10.0.0.4"))
visualizer.plot_graph() 
  

