from arango import ArangoClient
import argparse
import sys

def parse_args(argv):
    parser = argparse.ArgumentParser(description="Initialize ArangoDB")
    parser.add_argument("-n",
                        "--db_name",
                        action="store",
                        required=True,
                        help="DB Name")
    parser.add_argument("-c",
                        "--call_graph",
                        required=True,
                        help="Create call graph")
    parser.add_argument("-f",
                        "--force",
                        action="store_true",
                        required=False,
                        help="Force create new graph, deletes existing ones")

    args = parser.parse_args(argv)
    return args

def create_dep_graph(db_name, graph_name, vertex_name, edge_name, force):
    client = ArangoClient(hosts='http://localhost:8529')
    sys_db = client.db('_system', username='root', password='root')

    if not sys_db.has_database(db_name):
        db = sys_db.create_database(db_name)

    db = client.db(db_name, username='root', password='root')

    if db.has_graph(graph_name):
        if force:
            db.delete_graph(graph_name, drop_collections=True)
            db_graph = db.create_graph(graph_name)
        else:
            db_graph = db.graph(graph_name)
    else:
        db_graph = db.create_graph(graph_name)

    if not db_graph.has_vertex_collection(vertex_name):
        db_graph.create_vertex_collection(vertex_name)

    if not db_graph.has_edge_definition(edge_name):
        db_graph.create_edge_definition(
            edge_collection=edge_name,
            from_vertex_collections=[vertex_name],
            to_vertex_collections=[vertex_name]
        )

    if db_name == "sysfilter_scaled_down" and graph_name == "call_graph":
        if not db_graph.has_vertex_collection("bridges_reg"):
            db_graph.create_vertex_collection("bridges_reg")
        if not db_graph.has_vertex_collection("bridges_swap"):
            db_graph.create_vertex_collection("bridges_swap")
        if not db_graph.has_edge_definition("indirect_calls_out"):
            db_graph.create_edge_definition(
                edge_collection="indirect_calls_out",
                from_vertex_collections=[vertex_name],
                to_vertex_collections=['bridges_reg']
            )
        if not db_graph.has_edge_definition("indirect_calls_in"):
            db_graph.create_edge_definition(
                edge_collection="indirect_calls_in",
                from_vertex_collections=['bridges_reg'],
                to_vertex_collections=[vertex_name]
            )
        if not db_graph.has_edge_definition("indirect_calls_out"):
            db_graph.create_edge_definition(
                edge_collection="indirect_calls_out",
                from_vertex_collections=[vertex_name],
                to_vertex_collections=['bridges_swap']
            )
        if not db_graph.has_edge_definition("indirect_calls_in"):
            db_graph.create_edge_definition(
                edge_collection="indirect_calls_in",
                from_vertex_collections=['bridges_swap'],
                to_vertex_collections=[vertex_name]
            )

def main():
    args = parse_args(sys.argv[1:])
    db_name = args.db_name
    call_graph_name = args.call_graph

    if db_name == "sysfilter_scaled_down":
        if call_graph_name == "call_graph":
            create_dep_graph("sysfilter_scaled_down", "call_graph", "functions", "direct_calls", args.force)
        elif call_graph_name == "ldd_graph":
            create_dep_graph("sysfilter_scaled_down", "ldd_graph", "elf_bins", "depends_on", args.force)
        elif call_graph_name == "deb_graph":
            create_dep_graph("sysfilter_scaled_down", "deb_graph", "debs", "deb_depends", args.force)
if __name__=="__main__":
    main()

