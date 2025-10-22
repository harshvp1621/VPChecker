import json
import os
import multiprocessing
import traceback
from hashlib import sha256

from arango import ArangoClient

def get_hashed_str(input_str):
    return sha256(input_str.encode()).hexdigest()

def main():
    client = ArangoClient(hosts='http://localhost:8529')
    db = client.db('sysfilter_scaled_down', username='root', password='root')

    GRAPH_NAME = 'deb_graph'
    NODE_COLL_NAME = 'debs'
    EDGE_COLL_NAME = 'deb_depends'

    arango_deb_graph = db.graph(GRAPH_NAME)
    deb_vertex_collection = arango_deb_graph.vertex_collection(NODE_COLL_NAME)
    depends_edge_collection = arango_deb_graph.edge_collection(EDGE_COLL_NAME)
    elf_edge_collection = db.graph('ldd_graph').edge_collection('depends_on')
    elf_node_collection = db.graph('ldd_graph').vertex_collection('elf_bins')

    GET_ALL_EDGES_QUERY = f""" FOR e in depends_on
                            RETURN e
    """
    
    cursor = db.aql.execute(GET_ALL_EDGES_QUERY,count=True)

    ldd_graph_edge_list = [e for e in cursor]

    def get_elf_node(elf_id):
        GET_NODE_QUERY = f""" FOR e in elf_bins FILTER e._id == @elf_id RETURN e
        """
        elf_cursor = db.aql.execute(GET_NODE_QUERY,
                               bind_vars={'elf_id': f'{elf_id}'}
                                )
        return elf_cursor.pop()

    for ldd_edge in ldd_graph_edge_list:
        from_deb_node = get_elf_node(ldd_edge['_from'])
        to_deb_node = get_elf_node(ldd_edge['_to'])
        if not deb_vertex_collection.has(f"{NODE_COLL_NAME}/{from_deb_node['deb_name']}"):
            try:
                deb_vertex_collection.insert({
                        '_key': from_deb_node['deb_name']
                    })
            except Exception as e:
                print(f"Error adding node {from_deb_node['deb_name']}")
                print(str(traceback.format_exc()))


        if not deb_vertex_collection.has(f"{NODE_COLL_NAME}/{to_deb_node['deb_name']}"):
            try:
                deb_vertex_collection.insert({
                        '_key': to_deb_node['deb_name']
                    })
            except Exception as e:
                print(f"Error adding node {to_deb_node['deb_name']}")
                print(str(traceback.format_exc()))

        # Adding edges
        edge_key = get_hashed_str(f"{from_deb_node['deb_name']}_{to_deb_node['deb_name']}")
        if not depends_edge_collection.has(f"{EDGE_COLL_NAME}/{edge_key}"):
            try:
                depends_edge_collection.insert({
                    '_key' :  edge_key,
                    '_from' : f"{NODE_COLL_NAME}/{from_deb_node['deb_name']}",
                    '_to' : f"{NODE_COLL_NAME}/{to_deb_node['deb_name']}"
                    },
                    sync=True,
                        )
            except Exception as e:
                print(f"Error adding dependency edge from {from_deb_node['deb_name']} to {to_deb_node['deb_name']}")
                print(str(traceback.format_exc()))

if __name__=="__main__":
    main()
