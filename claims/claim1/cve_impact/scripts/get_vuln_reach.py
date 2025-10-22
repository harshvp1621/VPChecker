import os
from arango import ArangoClient
from collections import defaultdict
import csv
import json
from arango.http import DefaultHTTPClient
import multiprocessing
import itertools

class MyCustomHTTPClient(DefaultHTTPClient):
    REQUEST_TIMEOUT = 1000 # Set the timeout you want in seconds here

CALL_GRAPH = "call_graph"
CG_NODE_COLL = "functions"
CG_EDGE_COLL_DIR = "direct_calls"
CG_EDGE_COLL_INDIR_OUT = "indirect_calls_out"
CG_EDGE_COLL_INDIR_IN = "indirect_calls_in"

LDD_GRAPH = "ldd_graph"
LDD_NODE_COLL = "elf_bins"
LDD_EDGE_COLL = "depends_on"

CVE_NODE_COLL = "cves"
CVE_AFFECTS_EDGE_COLL = "cve_affects"

DEB_GRAPH = "deb_graph"
DEB_NODE_COLL = "debs"
DEB_EDGE_COLL = "deb_depends"

def get_arango_connection(pool_vuln_dict):
    global vuln_dict_shared
    vuln_dict_shared = pool_vuln_dict

    client = ArangoClient(hosts='http://localhost:8529', http_client=DefaultHTTPClient(request_timeout=100000))
    global db
    db = client.db('sysfilter', username='root', password='root')
    
    global call_graph
    call_graph = db.graph(CALL_GRAPH)

    global cg_node_list
    cg_node_list = call_graph.vertex_collection(CG_NODE_COLL)
    
    global ldd_graph
    ldd_graph = db.graph(LDD_GRAPH)

    global elf_nodes
    elf_nodes = ldd_graph.vertex_collection(LDD_NODE_COLL)

    global deb_graph
    deb_graph = db.graph(DEB_GRAPH)

    global deb_node_list
    deb_node_list = deb_graph.vertex_collection(DEB_NODE_COLL)

    global cve_affects_edge_coll
    cve_affects_edge_coll = call_graph.edge_collection(CVE_AFFECTS_EDGE_COLL)

def sanitize_name(name):
    if '~' in name:
        name = name.replace('~', '%7E')
    if '+' in name:
        name = name.replace('+', '%2B')
    return name

def get_doc(coll_name, doc_id):
    GET_QUERY=f"for f in {coll_name} FILTER f._id == @doc_id RETURN f"
    global db
    cursor = db.aql.execute(GET_QUERY, 
            bind_vars={'doc_id':doc_id},
            count=True)
    if cursor.count() == 1:
        for doc in cursor:
            return doc
    return None

def traverse_graph(target_graph, start_node, direction):
    '''
    Traverse the graph starting from the start_node in the specified direction

    Params:
        target_graph: Graph object to traverse
        start_node: Starting node in the graph
        direction: Direction of traversal (inbound/outbound)

    Returns:
        vertex_name_lst: List of vertices '_key' traversed
    '''
    # Keywords cannot be replaced with bind_vars
    GRAPH_TRAV_QUERY = f"""  FOR v,e,p
                        IN 1..6000000
                        {direction} @value
                        GRAPH @target_graph
                        OPTIONS {{ order:'bfs',
                                  uniqueVertices:'global' }}
                        RETURN v
                    """
    VALUE = f"{start_node}"
    global db
    cursor = db.aql.execute(
        GRAPH_TRAV_QUERY,
        bind_vars={'value': VALUE,
                   'target_graph': target_graph.name,}
    )

    vertex_lst = [ doc for doc in cursor ]

    print(f"BFS completed for {start_node}")

    return vertex_lst

def sbom_level_deb_reach(start_deb):
    '''
    Traverse the DEB graph. Traversal will be inbound towards the start deb.
    This will give the total number of deb packages affected
    '''

    aff_deb_list = traverse_graph(deb_graph, sanitize_name(start_deb), "INBOUND")
    result = [ deb['_key'] for deb in aff_deb_list ]
    if start_deb not in result:
        result.append(start_deb)
    print(f"Affected Debs based on SBOM-level {len(result)}")
    return result

def sbom_level_elf_reach(start_elf):
    '''
    Traverse the LDD graph. Traversal will be inbound towards the start
    elf. This will give us the total number of ELF binaries affected

    Params:
        start_elf: ELF Binary name in collection_name/bin_name format

    Returns:
        aff_elf_list: List of affected ELF binaries
    '''
    global ldd_graph

    start_elf = sanitize_name(start_elf)
    start_elf_node = get_doc(LDD_NODE_COLL, start_elf)
    if start_elf_node is None:
        print(f"xxxxxxxxxxxx Start ELF {start_elf} node not found xxxxxxxxx")
        return []

    aff_elf_list = traverse_graph(ldd_graph, sanitize_name(start_elf_node['_id']), "INBOUND")
    aff_elf_list.append(start_elf_node)

    # aff_ldd_list = []
    if aff_elf_list == []:
        print(f"Start node {start_elf} Issue")
        return []
    return aff_elf_list

def func_level_elf_reach(start_func):
    '''
    Traverse the Call graph. Traversal will be inbound towards the start
    function. This will give us the total number of functions affected by the vulnerable function.

    Params:
        start_func: Function name in collection_name/func_name format

    Returns:
        aff_elf_list: List of affected ELF
    '''
    global call_graph

    start_func_node = get_doc(CG_NODE_COLL, start_func)
    if start_func_node is None:
        print(f"xxxxxxxxxxxxxxxx Start Func node not found xxxxxxxxxxxxxxx")
        return []

    aff_func_list = traverse_graph(call_graph, sanitize_name(start_func_node['_id']), "INBOUND")
    aff_func_list.append(start_func_node)

    print(f"Total Affected Functions {len(aff_func_list)}")
    aff_elf_dict = {}
    for func in aff_func_list:
        if "-bridge" in func['_key'] or 'CVE-' in func['_key']:
            continue
        aff_elf_dict[func['lib']] = func['deb']

    return aff_elf_dict


def get_vulnerable_paths():
    pass

def cve_spread_task(cve_node, vuln_dict_shared):
    global cve_affects_edge_coll

    cve_affects_edges = cve_affects_edge_coll.edges(cve_node['_id'], direction='out')
    
    vuln_func_dict_list = []
    for cve_edge in cve_affects_edges['edges']:
        vuln_func = cve_edge['_to']
        vuln_elf = vuln_func.split("@")[1]
        vuln_deb = vuln_func.split("@")[2]

        elf_level_reach = sbom_level_elf_reach(f"{LDD_NODE_COLL}/{vuln_elf}@{vuln_deb}")
        func_level_reach = func_level_elf_reach(f"{vuln_func}")

        print("=====================================")
        print(f"---> For CVE {cve_node['_key']} and vuln func {vuln_func}, ELF level reach: {len(elf_level_reach)}, Function level reach: {len(func_level_reach)}")
        print("=====================================")

        vuln_func_dict = {
                "STATUS": cve_node['status'],
                "VULN_FUNC": vuln_func.split("/")[1],
                "VULN_ELF": vuln_elf,
                "VULN_DEB": vuln_deb,
                "ELF_REACH": len(elf_level_reach),
                "FUNC_REACH": len(func_level_reach)
            }
        vuln_func_key = vuln_func.split("/")[1]
        vuln_func_dict_list.append(vuln_func_dict)

    vuln_dict_shared.update({cve_node['_key']:vuln_func_dict_list})

def main():
    client_local = ArangoClient(hosts='http://localhost:8529', http_client=DefaultHTTPClient(request_timeout=100000))
    db_local = client_local.db('sysfilter', username='root', password='root')

    CVE_QUERY = f"""FOR cve IN {CVE_NODE_COLL} RETURN cve"""
    
    cve_cursor = db_local.aql.execute(CVE_QUERY, count=True)

    cve_node_list = [ c for c in cve_cursor if 'libxml2.so.2' in c['elf_list'] ]
    print(f"Processing {len(cve_node_list)} CVEs")
    vuln_dict_shared = multiprocessing.Manager().dict()

    # Adjust the number of processes based on the number of cores available
    # Make sure that ArangoDB is running and listening for http requests on port 8529 (See function get_arango_connection)
    pool = multiprocessing.Pool(initializer=get_arango_connection, initargs=(vuln_dict_shared, ), processes=os.cpu_count())
    pool.starmap(cve_spread_task, zip(cve_node_list, itertools.repeat(vuln_dict_shared)))

    with open("vuln_table.json", "w") as json_file:
        json.dump(vuln_dict_shared._getvalue(), json_file, indent=4)

if __name__=="__main__":
    main()
