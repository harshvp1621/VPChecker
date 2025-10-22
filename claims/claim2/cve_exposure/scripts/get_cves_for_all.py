# Usage: 
# $ conda activate supply_chain_py311
# $ python3 get_cves_for_all.py
import os
import json
from collections import defaultdict
import multiprocessing
import itertools

from arango import ArangoClient
from arango.http import DefaultHTTPClient

CVE_NODE_COLL_NAME = "cves"
CVE_AFFECTS_EDGE_COLL_NAME = "cve_affects"

LDD_NODE_COLL_NAME = "elf_bins"

# Make sure to create a results folder
RESULTS_DIR = "./results/"
os.makedirs(RESULTS_DIR, exist_ok=True)

vuln_func_cve_dict = defaultdict(list)
vuln_elf_cve_dict = defaultdict(list)

def get_arango_connection(pool_shared_dict):
    client = ArangoClient(hosts='http://localhost:8529', http_client=DefaultHTTPClient(request_timeout=100000))
    global db
    db = client.db('sysfilter', username='root', password='root')

    global shared_dict
    shared_dict = pool_shared_dict

def sanitize_name(name):
    if '~' in name:
        name = name.replace('~', '%7E')
    if '+' in name:
        name = name.replace('+', '%2B')
    return name

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
                   'depth': depth},
        ttl=1000000,
    )
    # print(f"Traversal for {start_node} done ")
    vertex_lst = [doc for doc in cursor]

    return vertex_lst

def get_vuln_reach_from_func(func_nodes):
    global db
    global vuln_func_cve_dict

    arango_call_graph = db.graph("call_graph")
    func_vuln_elf_reach = defaultdict(list)
    for func_node in func_nodes:
        trav_nodes = traverse_graph_depth(arango_call_graph, func_node['_id'], 60000000, "OUTBOUND")

        # Include the start node as well in the analysis
        trav_nodes.append(func_node)
        if len(trav_nodes) == 0:
            # print("func trav failed")
            continue
        for node in trav_nodes:
            if node['_id'] in vuln_func_cve_dict:
                func_vuln_elf_reach[node['lib']] += vuln_func_cve_dict[node['_id']]
    return func_vuln_elf_reach

def get_vuln_elf_reach(elf_node):
    global db
    global vuln_elf_cve_dict

    ldd_graph = db.graph("ldd_graph")
    vuln_elf_reach = defaultdict(list)
    elf_trav_nodes = traverse_graph_depth(ldd_graph, elf_node['_id'], 60000000, "OUTBOUND")

    # Include the start node as well in the traversal
    elf_trav_nodes.append(elf_node)

    if len(elf_trav_nodes) == 0:
        return {}
    for elf_node in elf_trav_nodes:
        if elf_node['_key'].split("@")[0] in vuln_elf_cve_dict:
            vuln_elf_reach[elf_node['_key']] += vuln_elf_cve_dict[elf_node['_key'].split("@")[0]]
    return vuln_elf_reach

def get_cves_task(exe_node, shared_dict):
    exe_name = exe_node['_key']
    print(f"Starting task {os.getpid()} {exe_name}")
    global db
    ldd_graph = db.graph("ldd_graph")
    FUNC_REC_QUERY = f""" FOR v in functions FILTER v.lib == @lib_name && v.deb == @deb_name RETURN v """
    cursor1 = db.aql.execute(
            FUNC_REC_QUERY,
            bind_vars={
                    'lib_name':exe_name.split("@")[0],
                    'deb_name':exe_node['deb_name'],
            },
            count=True,
            ttl=1000000,
    )
    func_nodes1 =  [ doc for doc in cursor1 ]
    func_nodes2 = []

    if func_nodes1 == []:
        cursor2 = db.aql.execute(
                FUNC_REC_QUERY,
                bind_vars={
                        'lib_name':exe_name.split("@")[0],
                        'deb_name':sanitize_name(exe_node['deb_name']),
                },
                count=True,
                ttl=1000000,
        ) 
        func_nodes2 =  [ doc for doc in cursor2 ]
    
    func_nodes = func_nodes1 + func_nodes2
    
    if func_nodes == []:
        print(f"No func nodes for {exe_name}")
        shared_dict[exe_name] = {"FUNC":[], "ELF":[]}
        with open(f"{RESULTS_DIR}/elf_cves_{os.getpid()}.json", "w") as f:
            f.write(json.dumps(shared_dict._getvalue()))
        return

    func_vuln_elf_reach_dict = get_vuln_reach_from_func(func_nodes)
    func_cve_list = []
    for elf, cve_list in func_vuln_elf_reach_dict.items():
        for cve in cve_list:
            if cve not in func_cve_list:
                func_cve_list.append(cve)

    elf_vuln_reach_dict = get_vuln_elf_reach(exe_node)
    elf_cve_list = []
    for elf, cve_list in elf_vuln_reach_dict.items():
        for cve in cve_list:
            if cve not in elf_cve_list:
                elf_cve_list.append(cve)

    exe_dict = {exe_name: {"FUNC":func_cve_list, "ELF":elf_cve_list} }
    shared_dict.update(exe_dict)
    print(f"{os.getpid()}: {exe_name} FUNC: {len(func_cve_list)} ELF: {len(elf_cve_list)}")
    with open(f"{RESULTS_DIR}/elf_cves_{os.getpid()}.json", "w") as f:
        f.write(json.dumps(shared_dict._getvalue()))

def main():
    CVE_QUERY = f"""FOR cve IN {CVE_NODE_COLL_NAME} RETURN cve"""

    client = ArangoClient(hosts='http://localhost:8529')
    db_conn = client.db('sysfilter', username='root', password='root')
    cve_cursor = db_conn.aql.execute(CVE_QUERY, count=True)
    cve_node_list = [c for c in cve_cursor]

    cve_affects_edge_collection = db_conn.graph('call_graph').edge_collection(CVE_AFFECTS_EDGE_COLL_NAME)

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

    # We create a list of executables
    INTERESTED_ELF_LIST = []
    count = 0
    
    ELF_QUERY = f"""FOR elf in {LDD_NODE_COLL_NAME} RETURN elf"""
    cursor = db_conn.aql.execute(ELF_QUERY)

    for elf_node in cursor:
        # Scaling this down to just compute reduction for coreutils binaries
        if "coreutils" in elf_node['deb_name']:
            INTERESTED_ELF_LIST.append(elf_node)

    print(f"Processing {len(INTERESTED_ELF_LIST)} elf nodes")
    
    manager = multiprocessing.Manager()
    shared_dict = manager.dict()
    
    # Modify the number of processes according to the number of cores available
    # Each worker process will produce a JSON of the format elf_cves_{os.getpid()}.json in the results dir
    # The final results were aggregated by reading the contents of all elf_cves_<PID>.json files
    # Make sure ArangoDB service is running and listening on for http connections on port 8529 (see get_arango_connection function)
    pool = multiprocessing.Pool(initializer=get_arango_connection, initargs=(shared_dict, ), processes=os.cpu_count())
    pool.starmap(get_cves_task, zip(INTERESTED_ELF_LIST, itertools.repeat(shared_dict)))
    
    with open(f"{RESULTS_DIR}/coreutils_cve_reduction.json", "w") as f:
        f.write(json.dumps(shared_dict._getvalue()))

if __name__=="__main__":
    main()
