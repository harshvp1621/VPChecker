import json
import os
import subprocess
import shlex
import requests
import copy
import dill
from collections import defaultdict
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import multiprocessing
from multiprocessing.managers import BaseManager, DictProxy
import importlib
import requests
import sys
from arango import ArangoClient
from arango.http import DefaultHTTPClient
from hashlib import sha256

def get_hashed_str(input_str):
    return sha256(input_str.encode()).hexdigest()

global_client = ArangoClient(hosts='http://localhost:8529', http_client=DefaultHTTPClient(request_timeout=10000))
global_db = global_client.db('sysfilter', username='root', password='root')

def args_to_str(arg_list):
    '''  This function will take a list of argument types eg: int, long, * etc
    and return a string which will be a representation of the args list
    [ "int", *, "char" ] will translate to the string "i*c"
    '''
    res = ""
    for arg in arg_list:
        res += arg[0]
    return res

def get_func_nodes_from_elf(elf_key):
    global global_db

    FUNCTION_LOOKUP_QUERY = f"""FOR v in functions
                            FILTER v.lib == @elf_name && v.deb == @deb_name
                            RETURN v"""
    tokens = elf_key.split("@")
    elf_name = tokens[0]
    deb_name = tokens[-1]

    cursor = global_db.aql.execute(FUNCTION_LOOKUP_QUERY,
            bind_vars={'elf_name':elf_name,
                       'deb_name':deb_name
            })
    func_dict = {}
    for node in cursor:
        func_dict[node['_key'].split("@")[0].split(".")[0]] = node
    return func_dict

def update_regular_functions_args(llvm_binfo, lib_func_dict):
    global global_db

    not_found = []
    for func, arg_info in llvm_binfo.items():
        if func not in lib_func_dict:
            not_found.append(func)
            print(f"Update Reg Args: {func} not found")
            continue
        func_node = lib_func_dict[func]
        UPD_QUERY=f"""UPDATE {{
                    '_key': @node_key,
                    'func_args': @func_args,
                    'func_args_list': @func_args_list
                }} IN functions OPTIONS {{ waitForSync: true }}
                """
        global_db.aql.execute(UPD_QUERY,
                bind_vars={
                "node_key":func_node['_key'],
                "func_args":len(arg_info['func_args']) ,
                "func_args_list": arg_info['func_args'],
                    })
    
    return not_found

def update_icall_site_args(llvm_binfo, lib_func_dict):
    global global_db
    not_icall = []
    targ_icall = []
    for func, args_info in llvm_binfo.items():
        if func not in lib_func_dict:
            continue
        func_node = lib_func_dict[func]
        if not args_info['icall_args'] and not func_node['implicit_source']:
            not_icall.append(func)
            continue
        
        UPD_QUERY=f"""UPDATE {{
                    '_key': @node_key,
                    'icall_args': @icall_args,
                    'icall_args_list': @icall_args_list
                }} IN functions OPTIONS {{ waitForSync: true }}
                """
        global_db.aql.execute(UPD_QUERY,
                bind_vars={
                "node_key": func_node['_key'],
                "icall_args": [ len(icall) for icall in args_info['icall_args'] ],
                "icall_args_list": args_info['icall_args'],
                    })
    return not_icall, targ_icall

def process_gtruth_file(file_path):
    def filter_args(args):
        return [arg for arg in args if not arg.isdigit() and '/' not in arg]

    with open(file_path, 'r') as file:
        lines = file.readlines()

    functions_dict = {}
    current_func = None

    for line in lines:
        if line.startswith("Function:"):
            parts = line.split()
            func_name = parts[1].split(".")[0]
            func_args = filter_args(parts[2:])
            functions_dict[func_name] = {"func_args": func_args, "icall_args": []}
            current_func = func_name
        elif line.startswith("Ind-call:") and current_func:
            ind_call_args = filter_args(line.split()[1:])
            functions_dict[current_func]["icall_args"].append(ind_call_args)

    return functions_dict

def get_doc(coll_name, doc_id):
    GET_QUERY=f"for f in {coll_name} FILTER f._id == @doc_id RETURN f"
    cursor = global_db.aql.execute(GET_QUERY,
                            bind_vars={'doc_id':doc_id},
                            count=True)
    if cursor.count() == 1:
        for doc in cursor:
            return doc
    return None

def check_doc_present(coll_name, doc_id):
    global global_db
    CHECK_QUERY=f"for f in {coll_name} FILTER f._id == @doc_id RETURN f"
    cursor = global_db.aql.execute(CHECK_QUERY,
                            bind_vars={'doc_id':doc_id},
                            count=True)
    if cursor.count():
        return True
    return False

def create_new_icall_connections(elf_node_name):
    global global_db
    # Insert Bridge nodes 
    # Make connections to match icall sites with implicit targets
    elf_name = elf_node_name.split("@")[0]
    deb_name = elf_node_name.split("@")[1]

    # This is after we update the function args and i-call args
    lib_func_dict_updated = get_func_nodes_from_elf(elf_node_name)

    func_args_dict = defaultdict(list)

    for func, func_node in lib_func_dict_updated.items():
        if 'func_args' not in func_node:
            continue
        if 'func_args_list' not in func_node:
            print(f"No args list {func_node['_key']}")
            continue
        func_args_dict[args_to_str(func_node['func_args_list'])].append(func_node)

    for args_sig in func_args_dict:
        llvm_bridge_key = f"Num_Args_{args_sig}_{elf_name}-bridge"

        if not check_doc_present('llvm_args_bridge', llvm_bridge_key):
            INSERT_STAT = f"""INSERT {{
                    '_key': @llvm_bridge_key,
                    'deb_name': @deb_name
                }} INTO llvm_args_bridge OPTIONS {{ overwriteMode: 'ignore', waitForSync: true }}"""

            global_db.aql.execute(INSERT_STAT,
                bind_vars={
                "llvm_bridge_key": llvm_bridge_key,
                "deb_name": deb_name,
                })

    for args_sig in func_args_dict:
        for func_node in func_args_dict[args_sig]:
            if not func_node['implicit_target']:
                # Skip any Non-Address-Taken function
                continue
            edge_key = get_hashed_str(f"Num_Args_{args_sig}_{elf_name}-bridge_{func_node['_key']}")
            if not check_doc_present('llvm_indir_calls_in', f"{edge_key}"):
                INSERT_STAT = f"""INSERT {{
                        '_key': @edge_key,
                        '_from': @source,
                        '_to': @target,
                    }} INTO llvm_indir_calls_in OPTIONS {{waitForSync: true, overwriteMode: 'ignore'}}"""
                global_db.aql.execute(INSERT_STAT,
                        bind_vars={
                            'edge_key': edge_key,
                            'source': f"llvm_args_bridge/Num_Args_{args_sig}_{elf_name}-bridge",
                            'target': f"functions/{func_node['_key']}"
                            })

    for func, func_node in lib_func_dict_updated.items():
        if func_node['implicit_source']:
            if 'icall_args' in func_node and 'icall_args_list' in func_node:
                for icall_site_args in func_node['icall_args_list']:
                    icall_site_args_sig = args_to_str(icall_site_args)
                    if icall_site_args_sig in func_args_dict:
                        edge_key = get_hashed_str(f"{func_node['_key']}_Num_Args_{icall_site_args_sig}_{elf_name}-bridge")
                        if not check_doc_present('llvm_indir_calls_out', f"{edge_key}"):
                            INSERT_STAT = f"""INSERT {{
                                        '_key': @edge_key,
                                        '_from': @source,
                                        '_to': @target,
                                    }} INTO llvm_indir_calls_in OPTIONS {{waitForSync: true, overwriteMode: 'ignore'}}"""
                            global_db.aql.execute(INSERT_STAT,
                                    bind_vars={
                                        'edge_key': edge_key,
                                        'source': f"functions/{func_node['_key']}",
                                        'target': f"llvm_args_bridge/Num_Args_{icall_site_args_sig}_{elf_name}-bridge"
                                        })

def main():
    elf_gtruth_file_dict = {
        "libavcodec.so.60@libavcodec60_7:6.1.1-4%2Bb4":"gtruth/libavcodec.so.60.31.102.bc.llvm",
        "libavfilter.so.9@libavfilter9_7:6.1.1-4%2Bb4":"gtruth/libavfilter.so.9.12.100.bc.llvm",
        "libcrypto.so.3@libssl3t64_3.2.2-1":"gtruth/libcrypto.so.3.bc.llvm",
        "libcurl.so.4@libcurl4t64_8.8.0-2":"gtruth/libcurl.so.4.8.0.bc.llvm",
        "libexpat.so.1@libexpat1_2.6.2-1":"gtruth/libexpat.so.1.9.2.bc.llvm",
        "libgnutls.so.30@libgnutls30t64_3.8.5-4":"gtruth/libgnutls.so.30.40.0.bc.llvm",
        "libnetsnmpmibs.so.40@libsnmp40t64_5.9.4%2Bdfsg-1.1%2Bb1":"gtruth/libnetsnmpmibs.so.40.2.1.bc.llvm",
        "libr_bin.so.5.9.2@libradare2-5.0.0t64_5.9.2%2Bdfsg-1":"gtruth/libr_arch.so.5.9.2.bc.llvm",
        "libr_core.so.5.9.2@libradare2-5.0.0t64_5.9.2%2Bdfsg-1":"gtruth/libr_core.so.5.9.2.bc.llvm",
        "libstb.so.0@libstb0t64_0.0%7Egit20230129.5736b15%2Bds-1.2":"gtruth/libstb.so.0.0.bc.llvm",
        "libtiff.so.6@libtiff6_4.5.1%2Bgit230720-4":"gtruth/libtiff.so.6.0.1.bc.llvm",
        "libxml2.so.2@libxml2_2.12.7%2Bdfsg-3":"gtruth/libxml2.so.2.12.7.bc.llvm",
        "libXpm.so.4@libxpm4_1:3.5.17-1%2Bb1":"gtruth/libXpm.so.4.11.0.bc.llvm"
    }
    '''elf_gtruth_file_dict = {"libxml2.so.2@libxml2_2.12.7+dfsg-3":"gtruth/libxml2.so.2.12.7.bc.llvm",}'''

    for elf_key, g_truth_file in elf_gtruth_file_dict.items():
        print(f"Processing {g_truth_file}")
        #g_truth_dets = process_gtruth_file(g_truth_file)
        #func_node_dict = get_func_nodes_from_elf(elf_key)
        #update_regular_functions_args(g_truth_dets, func_node_dict)
        #update_icall_site_args(g_truth_dets, func_node_dict)
        create_new_icall_connections(elf_key)

if __name__=="__main__":
    main()
