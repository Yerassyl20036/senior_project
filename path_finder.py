from visualize import FloodlightVisualizer
import networkx as nx


def get_shortest_path_and_cost(topology, src_label, dst_label):
    """
    Finds the shortest path from src_label to dst_label using NetworkX.
    - 'topology' is a NetworkX Graph built by FloodlightVisualizer.
    - 'src_label' and 'dst_label' are node labels, e.g. "h10.0.0.1" or "s00:00:..."

    Returns (path, cost).
      - path is a list of nodes in order, or None if no path.
      - cost is a simple sum of edges in the path, or 0 if no path.
    """
    # Validate nodes exist
    if src_label not in topology:
        print(f"[Error] Source node {src_label} not in graph.")
        return None, 0
    if dst_label not in topology:
        print(f"[Error] Destination node {dst_label} not in graph.")
        return None, 0

    # We’ll do an unweighted shortest path (fewest hops). If you want weights,
    # you'd store them in edge attributes and use a 'weight=' param in shortest_path.
    try:
        path = nx.shortest_path(topology, source=src_label, target=dst_label)
    except nx.NetworkXNoPath:
        print(f"[Error] No path between {src_label} and {dst_label}.")
        return None, 0

    # For an unweighted graph, "cost" can be length(path) - 1 if each hop costs 1.
    cost = len(path) - 1

    return path, cost


def main():
    fv = FloodlightVisualizer()
    fv.build_topology()  # Now fv.topology is a NetworkX graph
    
    shortest_path = fv.find_shortest_path("h22:a6:26:68:e1:4e", "h26:aa:cc:2a:26:a5")
    print(shortest_path)
    fv.draw_topology()


if __name__ == "__main__":
    main()
