import json
import os
import multiprocessing
import traceback
from hashlib import sha256
import subprocess
import shlex
import csv

import cxxfilt # For demangling C++ names
from arango import ArangoClient

elf_to_deb_map = json.load(open("../../data/elf_to_deb_map.json", "r"))

BIND_LOCAL = 0
BIND_GLOBAL = 1
BIND_WEAK = 2

JSON_FILE_DIR="../docker_vols/"

GRAPH_NAME = "call_graph"
NODE_COLL_NAME = "functions"
BRIDGE_NODE_COLL_NAME_REG = "bridges_reg"
BRIDGE_NODE_COLL_NAME_SWAP = "bridges_swap" # Swappable bridges for LLVM analysis
EDGE_COLL_NAME_DIR = "direct_calls"
EDGE_COLL_NAME_INDIR_IN = "indirect_calls_in"
EDGE_COLL_NAME_INDIR_OUT = "indirect_calls_out"

def get_arango_connection():
    client = ArangoClient(hosts='http://localhost:8529')
    global db
    db = client.db('sysfilter', username='root', password='root')
    
    # Will have special bridge nodes for this
    global vuln_deb_list
    vuln_deb_list = []
    with open("../data/FINAL_DEB_LIST_OF_APT_SRCS.txt", "r") as f:
        for line in f.readlines():
            vuln_deb_list.append(line.strip())

    global arango_call_graph
    arango_call_graph = db.graph(GRAPH_NAME)

    global func_vertex_collection
    func_vertex_collection = arango_call_graph.vertex_collection(NODE_COLL_NAME)
    
    # Handle bridge nodes in task function
    
    global edge_collection_dir
    edge_collection_dir = arango_call_graph.edge_collection(EDGE_COLL_NAME_DIR)
    
    global edge_collection_indir_out
    edge_collection_indir_out = arango_call_graph.edge_collection(EDGE_COLL_NAME_INDIR_OUT)

    global edge_collection_indir_in
    edge_collection_indir_in = arango_call_graph.edge_collection(EDGE_COLL_NAME_INDIR_IN)

def sanitize_deb_name(name):
    if '~' in name:
        name = name.replace('~', '%7E')
    if '+' in name:
        name = name.replace('+', '%2B')
    return name

def traverse_graph(target_graph, start_node, direction):
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
    cursor = db.aql.execute(
        GRAPH_TRAV_QUERY,
        bind_vars={'value': VALUE,
                   'target_graph': target_graph,},
                   count=True
    )
    if cursor.count == 0:
        print(f"Empty Cursor for node {start_node}")

    vertex_lst = []
    for doc in cursor:
        vertex_lst.append(doc['_key'])

    return vertex_lst

def get_hashed_str(input_str):
    return sha256(input_str.encode()).hexdigest()

def arango_cap_str(f_name, elf_name, deb_name):
    key_str = f"{f_name}@{elf_name}@{deb_name}"
    if len(key_str) > 254:
        return f"{get_hashed_str(key_str)}@{elf_name}@{deb_name}"
    return key_str

def create_elf_to_deb_map(curr_deb, elf_dep_list):
    curr_deb = sanitize_deb_name(curr_deb)
    res_dict = {}
    curr_deb_deps = traverse_graph('deb_graph', f'debs/{curr_deb}', "OUTBOUND")
    curr_deb_deps.append(curr_deb) # Traversal does not include the start node
    
    curr_deb_deps_sanitized = [ sanitize_deb_name(deb) for deb in curr_deb_deps ]

    for elf in elf_dep_list:
        if elf not in elf_to_deb_map:
            res_dict[elf] = f"unresolved_map_{elf}"
            continue
        elf_debs = elf_to_deb_map[elf]
        # print(f"ELF {elf} shipped by {elf_debs}")
        for deb in elf_debs:
            deb = sanitize_deb_name(deb)
            if deb in curr_deb_deps_sanitized:
                res_dict[elf] = deb
                break
        if elf_debs == []:
            res_dict[elf] = f"unresolved_deb_dep_{elf}"

    return res_dict

def process_tar(fcg_file):
    deb_name = fcg_file.split("/")[-2]
    elf_name = ""

    elf_csv = f"{fcg_file.split('.fcg')[0]}_{deb_name}_ELF64_elf_info.csv"

    try:
        with open(elf_csv, "r") as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=",")
            for row in csv_reader:
                # Always rely on SONAMES extracted from the readelf header
                if row[0] == "SONAME":
                    elf_name = row[1]
    except:
        print(str(traceback.format_exc()))
        return 0

    ERROR_FILE = f"{fcg_file.split}.arango.error"
    global db
    try:
        process_fcg(fcg_file, elf_name, sanitize_deb_name(deb_name))
    except Exception as e:
        with open(ERROR_FILE, 'a+') as error_file:
            error_file.write(str(traceback.format_exc()))
        return 0

    return 0


def process_fcg(fcg_json_file, elf_name, deb_name):
    # print(f"Processing {fcg_json_file}")
    # print(f"Starting in PID {os.getpid()}")
    global db
    global arango_call_graph
    global vuln_deb_list
    global EDGE_COLL_NAME_DIR
    global EDGE_COLL_NAME_INDIR_IN
    global EDGE_COLL_NAME_INDIR_OUT
    global BRIDGE_NODE_COLL_NAME_REG
    global BRIDGE_NODE_COLL_NAME_SWAP

    BRIDGE_NODE_COLL_NAME = BRIDGE_NODE_COLL_NAME_REG
    # Strip off the version string for now
    if deb_name.split("_")[0] in vuln_deb_list:
        BRIDGE_NODE_COLL_NAME = BRIDGE_NODE_COLL_NAME_SWAP

    bridge_vertex_collection = arango_call_graph.vertex_collection(BRIDGE_NODE_COLL_NAME)
    global func_vertex_collection
    global edge_collection_dir
    global edge_collection_indir_out
    global edge_collection_indir_in

    def check_doc_present(coll_name, doc_id):
        CHECK_QUERY=f"for f in {coll_name} FILTER f._id == @doc_id RETURN f"
        cursor = db.aql.execute(CHECK_QUERY, 
                                bind_vars={'doc_id':doc_id},
                                count=True)
        if cursor.count():
            return True
        return False
    
    def get_doc(coll_name, doc_id):
        GET_QUERY=f"for f in {coll_name} FILTER f._id == @doc_id RETURN f"
        cursor = db.aql.execute(GET_QUERY, 
                                bind_vars={'doc_id':doc_id},
                                count=True)
        if cursor.count() == 1:
            for doc in cursor:
                return doc
        return None

    try:
        with open(fcg_json_file, "r") as f:
            lines = f.readlines()
            # First two lines are some sysfilter debug prints
            sysfilter_analysis = json.loads(lines[2].strip())
    except Exception as e:
        print(str(traceback.format_exc()))
        print(fcg_json_file)
        return

    DONE_FILE = f"{fcg_json_file.split('.extracted')[0]}.arango.done"
    ERROR_FILE = f"{fcg_json_file.split('.extracted')[0]}.arango.error"

    executable_path = ""
    if "(executable)" in sysfilter_analysis["analysis_scope"].keys():
        executable_path = sysfilter_analysis["analysis_scope"]["(executable)"]["path"]
    else:
        for p in sysfilter_analysis["analysis_scope"].keys():
            if p.startswith("/"):
                executable_path = p
                break
    if executable_path == "":
        with open(ERROR_FILE, 'a+') as error_file:
            print(f"Error reading json {fcg_json_file}\n")
            error_file.write(f"Error reading json {fcg_json_file}\n")
            error_file.write(str(traceback.format_exc()))
            return

    executable_name = os.path.basename(executable_path)

    # deb_name = fcg_json_file.split("/")[-2]

    # List of libraries on which this executable depends
    lib_deps = []
    analysis_scope_bins = sysfilter_analysis["analysis_scope"]
    for bin_name in analysis_scope_bins:
        if bin_name == "(executable)":
            continue
        if bin_name.startswith("/"):
            bin_name = os.path.basename(bin_name)
        lib_deps.append(bin_name)

    deb_dict = create_elf_to_deb_map(deb_name, lib_deps)
    deb_dict[executable_name] = deb_name

    sysfilter_call_graph = sysfilter_analysis["vacuum"]["analysis"]["all"]["callgraph"]

    all_funcs = sysfilter_call_graph["funcs"]

    with open(DONE_FILE, 'a+') as done_file:
        done_file.write(f"Processing {executable_name}...\n")

    ################### ADD ERROR FILES and DONE FILES, use python logging module for exceptions
    for func_obj, func_dict in all_funcs.items():
        # f_name = func_dict["name"].split(".")[0]
        f_name = func_dict["name"]
        elf_name = executable_name if (func_dict["lib"] == "(executable)") else func_dict["lib"]
        if elf_name.startswith("/"):
            elf_name = os.path.basename(elf_name)

        v_name = ""
        try:
            v_name = arango_cap_str(f_name, elf_name, deb_dict[elf_name])
        except:
            with open(ERROR_FILE, 'a+') as error_file:
                error_file.write(f"Error resolving elf {elf_name} mappings for vertex {v_name}\n")
                error_file.write(f"{deb_dict}")
                error_file.write(str(traceback.format_exc()))
            deb_dict[elf_name] = f"{elf_name}_unresolved"
            v_name = arango_cap_str(f_name, elf_name, deb_dict[elf_name])

        # Hack for now
        if not "symbol_size" in func_dict:
            func_dict["symbol_size"] = 0
        if not "binding_type" in func_dict:
            func_dict["binding_type"] = BIND_LOCAL

        f_name_demangled = ""
        
        # Don't remember why the block below was added
        #try:
        #    func_vertex_collection.has(f"{NODE_COLL_NAME}/{v_name}")
        #except:
        #    print(v_name)
        #    print(str(traceback.format_exc()))
        
        try:
            f_name_demangled = cxxfilt.demangle(f_name)
        except:
            f_name_demangled = f_name
        # if not func_vertex_collection.has(f"{NODE_COLL_NAME}/{v_name}"):
        if not check_doc_present(NODE_COLL_NAME, f"{NODE_COLL_NAME}/{v_name}"):
            try:
                INSERT_STAT = f"""INSERT {{
                    '_key': @v_name,
                    'name': @f_name_demangled,
                    'size': @func_size,
                    'lib': @elf_name,
                    'deb': @deb_name,
                    'exported': @exported,
                    'implicit_source': @implicit_source,
                    'implicit_target': @implicit_target,
                }} INTO {NODE_COLL_NAME} OPTIONS {{ overwriteMode: 'ignore', waitForSync: true }}"""
                
                db.aql.execute(INSERT_STAT, 
                    bind_vars={
                    "v_name": v_name,
                    "f_name_demangled": f_name_demangled,
                    "func_size": func_dict['symbol_size'],
                    'elf_name': elf_name,
                    'deb_name': deb_dict[elf_name],
                    'exported': ((func_dict['dynamic_symbol'] and (func_dict['binding_type'] == BIND_GLOBAL)) or (func_dict['binding_type'] == BIND_WEAK)),
                    'implicit_source': func_dict['implicit_source'],
                    'implicit_target': func_dict['implicit_target']
                    })
            except Exception as e:
                with open(ERROR_FILE, 'a+') as error_file:
                    error_file.write(f"Error adding vertex {v_name}\n")
                    error_file.write(str(traceback.format_exc()))
                # print(f"Error adding vertex {v_name}")
                # print(traceback.format_exc())
        else:
            func_node = get_doc(NODE_COLL_NAME, f"{NODE_COLL_NAME}/{v_name}")
            if func_dict['implicit_target'] and not func_node['implicit_target']:
                UPD_QUERY=f"""UPDATE {{
                    '_key': @v_name,
                    'implicit_target': @func_implicit_target,
                    'at_upd': @isupdated
                }} IN {NODE_COLL_NAME} OPTIONS {{ waitForSync: true }}
                """
                db.aql.execute(UPD_QUERY,
                        bind_vars={
                        "v_name": v_name,
                        "func_implicit_target": func_dict['implicit_target'],
                        "isupdated": True
                            })
            # If this function is not an implicit target already in the database,
            # and the new CG declares this as implicit target, then update the attributes of the node
            # in the database

    direct_edges = sysfilter_call_graph["direct_edges"]
    for func, edge_list in direct_edges.items():
        src_elf = executable_name if (func.split("@")[0] == "(executable)") else func.split("@")[0]
        if src_elf.startswith("/"):
            src_elf = os.path.basename(src_elf)
        # src_func = func.split("@", 1)[1].split("+")[0].split(".")[0]
        src_func = func.split("@", 1)[1].split("+")[0]

        for target in edge_list:
            target_elf = executable_name if (target.split("@")[0] == "(executable)") else target.split("@")[0]
            if target_elf.startswith("/"):
                target_elf = os.path.basename(target_elf)
            # target_func = target.split("@", 1)[1].split("+")[0].split(".")[0]
            target_func = target.split("@", 1)[1].split("+")[0]

            src_v_name = arango_cap_str(src_func, src_elf, deb_dict[src_elf])
            # src_v_name = f"{src_func}@{src_elf}"
            target_v_name = arango_cap_str(target_func, target_elf, deb_dict[target_elf])
            # target_v_name = f"{target_func}@{target_elf}"

            if src_v_name == target_v_name:
                # Weirdly sysfilter has self edges
                continue

            edge_key = get_hashed_str(f"{src_v_name}_{target_v_name}")
            if not check_doc_present(EDGE_COLL_NAME_DIR, f"{EDGE_COLL_NAME_DIR}/{edge_key}"):
                try:
                    INSERT_STAT = f"""INSERT {{
                        '_key': @edge_key,
                        '_from': @source,
                        '_to': @target,
                    }} INTO {EDGE_COLL_NAME_DIR} OPTIONS {{waitForSync: true, overwriteMode: 'ignore'}}"""
                    db.aql.execute(INSERT_STAT,
                            bind_vars={
                                'edge_key': edge_key,
                                'source': f'{NODE_COLL_NAME}/{src_v_name}',
                                'target': f'{NODE_COLL_NAME}/{target_v_name}'
                                })
                except Exception as e:
                    with open(ERROR_FILE, 'a+') as error_file:
                        error_file.write(f"Error adding direct edge {src_v_name} -> {target_v_name}\n")
                        error_file.write(str(traceback.format_exc()))
                    # print(f"Error adding edge {src_v_name} -> {target_v_name}")
                    # print(traceback.format_exc())
        # split
    indirect_sources = sysfilter_call_graph["indirect_sources"]
    indirect_targets = sysfilter_call_graph["indirect_targets"]

    for ind_src in indirect_sources:
        src_elf = executable_name if (ind_src.split("@")[0] == "(executable)") else ind_src.split("@")[0]
        if src_elf.startswith("/"):
            src_elf = os.path.basename(src_elf)
        # src_func = ind_src.split("@", 1)[1].split("+")[0].split(".")[0]
        src_func = ind_src.split("@", 1)[1].split("+")[0]
        ind_srv_v_name = arango_cap_str(src_func, src_elf, deb_dict[src_elf])
        bridge_key = f"{src_elf}@{deb_dict[src_elf]}-bridge"

        if not check_doc_present(BRIDGE_NODE_COLL_NAME, f"{BRIDGE_NODE_COLL_NAME}/{bridge_key}"):
            try:
                INSERT_STAT=f"""INSERT {{
                    '_key': @bridge_key,
                    'name': @src_elf,
                    'deb': @deb_name
                }} INTO {BRIDGE_NODE_COLL_NAME} OPTIONS {{waitForSync: true, overwriteMode: 'ignore'}}"""
                db.aql.execute(INSERT_STAT,
                        bind_vars={
                            'bridge_key': bridge_key,
                            'src_elf': src_elf,
                            'deb_name': deb_dict[src_elf]
                            })
            except Exception as e:
                with open(ERROR_FILE, 'a+') as error_file:
                    error_file.write(f"Error adding bridge vertex {src_elf}\n")
                    error_file.write(str(traceback.format_exc()))
                # print(f"Error adding bridge vertex {src_elf}")
                # print(traceback.format_exc())

        edge_to_bridge_key = get_hashed_str(f"{ind_srv_v_name}_{bridge_key}")
        if not check_doc_present(EDGE_COLL_NAME_INDIR_OUT, f"{EDGE_COLL_NAME_INDIR_OUT}/{edge_to_bridge_key}"):
            try:
                INSERT_STAT = f"""INSERT {{
                        '_key': @edge_to_bridge_key,
                        '_from': @source,
                        '_to': @target,
                    }} INTO {EDGE_COLL_NAME_INDIR_OUT} OPTIONS {{waitForSync: true, overwriteMode: 'ignore'}}"""
                    
                db.aql.execute(INSERT_STAT,
                        bind_vars={
                            'edge_to_bridge_key': edge_to_bridge_key,
                            'source': f'{NODE_COLL_NAME}/{ind_srv_v_name}',
                            'target': f'{BRIDGE_NODE_COLL_NAME}/{bridge_key}'
                            })
            except Exception as e:
                with open(ERROR_FILE, 'a+') as error_file:
                    error_file.write(f"Error adding indirect edge {ind_srv_v_name} -> {bridge_key} with key {edge_to_bridge_key}\n")
                    error_file.write(str(traceback.format_exc()))
                # print(f"Error adding indirect edge {ind_srv_v_name} -> {src_elf}-bridge")
                # print(traceback.format_exc())

    for ind_tar in indirect_targets:
        target_elf = executable_name if (ind_tar.split("@")[0] == "(executable)") else ind_tar.split("@")[0]
        if target_elf.startswith("/"):
            target_elf = os.path.basename(target_elf)

        target_func = ind_tar.split("@", 1)[1].split("+")[0]

        ind_tar_v_name = arango_cap_str(target_func, target_elf, deb_dict[target_elf])
        bridge_key = f"{target_elf}@{deb_dict[target_elf]}-bridge"

        if not check_doc_present(BRIDGE_NODE_COLL_NAME, f"{BRIDGE_NODE_COLL_NAME}/{bridge_key}"):
            try:
                INSERT_STAT=f"""INSERT {{
                    '_key': @bridge_key,
                    'name': @target_elf,
                    'deb': @deb_name
                }} INTO {BRIDGE_NODE_COLL_NAME} OPTIONS {{waitForSync: true, overwriteMode: 'ignore'}}"""
                
                db.aql.execute(INSERT_STAT,
                        bind_vars={
                            'bridge_key': bridge_key,
                            'target_elf': target_elf,
                            'deb_name': deb_dict[target_elf],
                            })
            except Exception as e:
                with open(ERROR_FILE, 'a+') as error_file:
                    error_file.write(f"Error adding bridge vertex {target_elf}\n")
                    error_file.write(str(traceback.format_exc()))
                # print(f"Error adding bridge vertex {target_elf}")
                # print(traceback.format_exc())

        edge_from_bridge_key = get_hashed_str(f"{bridge_key}_{ind_tar_v_name}")
        if not check_doc_present(EDGE_COLL_NAME_INDIR_IN, f"{EDGE_COLL_NAME_INDIR_IN}/{edge_from_bridge_key}"):
            try:
                INSERT_STAT = f"""INSERT {{
                        '_key': @edge_from_bridge_key,
                        '_from': @source,
                        '_to': @target,
                    }} INTO {EDGE_COLL_NAME_INDIR_IN} OPTIONS {{waitForSync: true, overwriteMode: 'ignore'}}"""
                    
                db.aql.execute(INSERT_STAT,
                        bind_vars={
                            'edge_from_bridge_key': edge_from_bridge_key,
                            'source': f'{BRIDGE_NODE_COLL_NAME}/{bridge_key}',
                            'target': f'{NODE_COLL_NAME}/{ind_tar_v_name}'
                            })
            except Exception as e:
                with open(ERROR_FILE, 'a+') as error_file:
                    error_file.write(f"Error adding indirect edge {bridge_key} -> {ind_tar_v_name} with key {edge_from_bridge_key}\n")
                        # print(f"Error adding indirect edge {target_elf}-bridge -> {ind_tar_v_name}")
                        # print(traceback.format_exc())
                    error_file.write(str(traceback.format_exc()))

    with open(DONE_FILE, 'a+') as done_file:
        done_file.write("DONE\n")
    #########################################

def main():

    fcg_json_file_list = []

    for top_dir, sub_dirs, files in os.walk(f"{JSON_FILE_DIR}/", topdown=False):
        for file_name in files:
            full_file_path = os.path.join(top_dir, file_name)
            if "/LIBS/libs/" in full_file_path:
                continue
            # Ignore Symlinks
            if os.path.islink(full_file_path):
                continue
            if full_file_path.endswith(".fcg.json"):
                if os.path.exists(f"{full_file_path}.arango.done"):
                    continue
                fcg_json_file_list.append(full_file_path)

    print(f"Processing {len(fcg_json_file_list)} call graphs")
    pool = multiprocessing.Pool(initializer=get_arango_connection, processes=48)

    pool.map(process_tar, fcg_json_file_list)

if __name__=="__main__":
    main()
