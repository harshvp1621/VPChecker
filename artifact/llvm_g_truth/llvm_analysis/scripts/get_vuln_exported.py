import os
import sys
import json
from collections import defaultdict
import multiprocessing
import itertools

from arango import ArangoClient
from arango.http import DefaultHTTPClient

class MyCustomHTTPClient(DefaultHTTPClient):
    REQUEST_TIMEOUT = 1000

db = None
def get_arango_connection(pool_shared_dict):
    client = ArangoClient(hosts='http://localhost:8529', http_client=DefaultHTTPClient(request_timeout=1000000))
    global db
    db = client.db('sysfilter', username='root', password='root')

    global shared_dict
    shared_dict = pool_shared_dict

CVE_NODE_COLL_NAME = "cves"
CVE_AFFECTS_EDGE_COLL_NAME = "cve_affects"

LDD_NODE_COLL_NAME = "elf_bins"

RESULTS_DIR = "./results"
os.makedirs(RESULTS_DIR, exist_ok=True)

vuln_elf_2_vuln_func_dict = defaultdict(list)
vuln_func_cve_dict = defaultdict(list)
vuln_elf_cve_dict = defaultdict(list)

def traverse_graph_depth(target_graph, start_node, depth, direction):
    '''
    Traverse the graph starting from the start_node in the specified direction

    Params:
        target_graph: Graph object to traverse
        start_node: Starting node in the graph
        direction: Direction of traversal (inbound/outbound)

    Returns:
        vertex_name_lst: List of vertices '_key' traversed
    '''
    global db
    # Keywords cannot be replaced with bind_vars
    GRAPH_TRAV_QUERY = f"""  FOR v,e,p
                        IN 1..@depth
                        {direction} @value
                        GRAPH @target_graph
                        OPTIONS {{ order:'bfs',
                                  uniqueVertices:'global' }}
                        RETURN v
                    """
    VALUE = f"{start_node}"
    cursor = db.aql.execute(
        GRAPH_TRAV_QUERY,
        bind_vars={'value': VALUE,
                   'target_graph': target_graph.name,
                   'depth': depth}
    )
    # print(f"Traversal for {start_node} done ")
    vertex_lst = [doc for doc in cursor]

    return vertex_lst

def get_func_nodes_for_elf(lib_name):
    FUNC_REC_QUERY = f""" FOR v in functions FILTER v.lib == @lib_name RETURN v """
    global db
    cursor = db.aql.execute(
            FUNC_REC_QUERY,
            bind_vars={
                    'lib_name':lib_name
            },
            count=True
    )
    if cursor.count == 0:
        return []
    return [ doc for doc in cursor ]

def get_vuln_reach_from_func(func_nodes, scope_elf_name):
    global db
    arango_call_graph = db.graph("call_graph")
    vuln_func_reach = defaultdict(list)
    

    global vuln_func_cve_dict
    global vuln_elf_2_vuln_func_dict

    for func_node in func_nodes:
        trav_nodes = traverse_graph_depth(arango_call_graph, func_node['_id'], 60000000, "OUTBOUND")
        if len(trav_nodes) == 0:
            continue
        # print(f"In BFS {len(trav_nodes)} number of nodes for func {func_node['_id']}")
        for node in trav_nodes:
            if node['_id'] in vuln_elf_2_vuln_func_dict[scope_elf_name]:
                vuln_func_reach[func_node['_id']] += vuln_func_cve_dict[node['_id']]

    for start_func, cves in vuln_func_reach.items():
        vuln_func_reach[start_func] = list(set(cves))
    # print(f"Func vuln deb reach {len(func_deb_reach)}")
    return vuln_func_reach

def get_vuln_reach_from_func_generic(func_nodes):
    global db
    arango_call_graph = db.graph("call_graph")
    vuln_func_reach = defaultdict(list)
    

    global vuln_func_cve_dict
    global vuln_elf_2_vuln_func_dict

    for func_node in func_nodes:
        trav_nodes = traverse_graph_depth(arango_call_graph, func_node['_id'], 60000000, "OUTBOUND")
        if len(trav_nodes) == 0:
            continue
        # print(f"In BFS {len(trav_nodes)} number of nodes for func {func_node['_id']}")
        for node in trav_nodes:
            if node['_id'] in vuln_func_cve_dict:
                vuln_func_reach[func_node['_id']] += vuln_func_cve_dict[node['_id']]

    for start_func, cves in vuln_func_reach.items():
        vuln_func_reach[start_func] = list(set(cves))
    # print(f"Func vuln deb reach {len(func_deb_reach)}")
    return vuln_func_reach

def get_cves_task(exe_node, shared_dict):
    exe_name = exe_node['_key']
    print(f"Starting task {os.getpid()} {exe_name}")
    global db

    FUNC_REC_QUERY = f""" FOR v in functions FILTER v.lib == @lib_name && v.deb == @deb_name RETURN v """
    cursor = db.aql.execute(
            FUNC_REC_QUERY,
            bind_vars={
                    'lib_name':exe_name.split("@")[0],
                    'deb_name':exe_node['deb_name'],
            },
            count=True
    )

    exported_funcs = []
    all_funcs = []
    vuln_reach = []
 
    all_funcs = [ f for f in cursor ]

    for f in all_funcs:
        if f['exported']:
            exported_funcs.append(f)

    if exported_funcs == []:
        exe_dict = {exe_name: {"VULN":[], "EXPORTED":len(exported_funcs), "TOTAL":len(all_funcs), "CVES_REACHED":[]} }
        shared_dict.update(exe_dict)
        print(f"No exported functions for {exe_name}")
        with open(f"{RESULTS_DIR}/vuln_paths/vuln_paths_{os.getpid()}.json", "w") as f:
            f.write(json.dumps(shared_dict._getvalue()))
        return
    
    vuln_reach = get_vuln_reach_from_func_generic(exported_funcs)
    tot_reachable_cves = []
    for f, cve_list in vuln_reach.items():
        for cve_id in cve_list:
            tot_reachable_cves.append(cve_id)
    tot_reachable_cves = list(set(tot_reachable_cves))

    exe_dict = {exe_name: {"VULN":[ f for f in vuln_reach ], "EXPORTED":[ f['_id'] for f in exported_funcs ], "TOTAL":[ f['_id'] for f in all_funcs ], "CVES_REACHED": tot_reachable_cves}}
    shared_dict.update(exe_dict)
    print(f"{os.getpid()}: {exe_name} VULN: {len(vuln_reach)} EXPORTED: {len(exported_funcs)} TOTAL: {len(all_funcs)}")
    with open(f"{RESULTS_DIR}/vuln_paths/vuln_paths_{os.getpid()}.json", "w") as f:
        f.write(json.dumps(shared_dict._getvalue()))

def main():
    if len(sys.argv) > 1:
        run_type = sys.argv[1]
    else:
        run_type = "syfilter"
    
    CVE_QUERY = f"""FOR cve IN {CVE_NODE_COLL_NAME} RETURN cve"""

    client = ArangoClient(hosts='http://localhost:8529')
    db_conn = client.db('sysfilter', username='root', password='root')
    cve_cursor = db_conn.aql.execute(CVE_QUERY, count=True)
    cve_node_list = [c for c in cve_cursor]

    cve_affects_edge_collection = db_conn.graph('call_graph').edge_collection(CVE_AFFECTS_EDGE_COLL_NAME)
    
    def get_doc(coll_name, doc_id):
        GET_QUERY=f"for f in {coll_name} FILTER f._id == @doc_id RETURN f"
        cursor = db_conn.aql.execute(GET_QUERY,
                                bind_vars={'doc_id':doc_id},
                                count=True)
        if cursor.count() == 1:
            for doc in cursor:
                return doc
        return None
    
    global vuln_func_cve_dict
    for cve_node in cve_node_list:
        cve_id = int(cve_node['_key'].split('-')[1])
        if cve_id < 2022:
            continue
        cve_affects_edges = cve_affects_edge_collection.edges(cve_node['_id'], direction='out')
        for cve_edge in cve_affects_edges['edges']:
            vuln_func = cve_edge['_to']
            vuln_func_cve_dict[vuln_func].append(cve_node['_key'])

    global vuln_elf_cve_dict
    for cve_node in cve_node_list:
        cve_id = int(cve_node['_key'].split('-')[1])
        if cve_id < 2022:
            continue
        for elf in cve_node['elf_list']:
            vuln_elf_cve_dict[elf].append(cve_node['_key'])

    global vuln_elf_2_vuln_func_dict
    for cve_node in cve_node_list:
        cve_id = int(cve_node['_key'].split('-')[1])
        if cve_id < 2022:
            continue
        cve_affects_edges = cve_affects_edge_collection.edges(cve_node['_id'], direction='out')
        for cve_edge in cve_affects_edges['edges']:
            vuln_func_node = get_doc('functions', cve_edge['_to'])
            vuln_elf_2_vuln_func_dict[vuln_func_node['lib']].append(vuln_func_node['_id'])

    LIB_QUERY = f"""FOR lib IN {LDD_NODE_COLL_NAME} FILTER lib.type == 'SHARED' RETURN lib"""
    cursor = db_conn.aql.execute(LIB_QUERY)
    INTERESTED_LIB_LIST = [ ]
    target_libs = []
    with open("../data/llvm_target_libs.txt", "r") as f:
        for line in f.readlines():
            target_libs.append(line.strip())
    for elf in cursor:
        if elf['_key'].split("@")[0] in target_libs:
            INTERESTED_LIB_LIST.append(elf)

    print(f"Processing {len(INTERESTED_LIB_LIST)} LIBS")
    manager = multiprocessing.Manager()
    shared_dict = manager.dict()

    pool = multiprocessing.Pool(initializer=get_arango_connection, initargs=(shared_dict, ), processes=os.cpu_count())
    pool.starmap(get_cves_task, zip(INTERESTED_LIB_LIST, itertools.repeat(shared_dict)))
    with open(f"{RESULTS_DIR}/vuln_paths_{run_type}.json", "w") as f:
        f.write(json.dumps(shared_dict._getvalue()))

if __name__=="__main__":
    main()
