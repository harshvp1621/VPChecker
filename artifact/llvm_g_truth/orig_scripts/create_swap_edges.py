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

call_graph = global_db.graph('call_graph')

QUERY=f"""FOR edge in indirect_calls_in FILTER edge._from LIKE @value RETURN edge"""
cursor = global_db.aql.execute(QUERY, bind_vars={'value':"bridges_swap/%"}, count=True)

indir_calls_in_list = [ e for e in cursor ]
print(f"Processing {len(indir_calls_in_list)} Indirect In Edges")

for old_edge in indir_calls_in_list:
    src_node = old_edge['_from']
    target_node = old_edge['_to']

    new_edge_key = get_hashed_str(f"{src_node}__{target_node}__swap")

    DELETE_STAT=f"""REMOVE @old_edge IN indirect_calls_in OPTIONS {{waitForSync: true}}
    """
    global_db.aql.execute(DELETE_STAT, bind_vars={'old_edge':old_edge['_key']})

    '''
    INSERT_STAT = f"""INSERT {{
                        '_key': @edge_key,
                        '_from': @source,
                        '_to': @target,
                    }} INTO indirect_calls_in_swap OPTIONS {{waitForSync: true, overwriteMode: 'ignore'}}"""
    global_db.aql.execute(INSERT_STAT,
            bind_vars={
                'edge_key': new_edge_key,
                'source': src_node,
                'target': target_node
                })
    '''

QUERY=f"""FOR edge in indirect_calls_out FILTER edge._to LIKE @value RETURN edge"""
cursor = global_db.aql.execute(QUERY, bind_vars={'value':"bridges_swap/%"}, count=True)

indir_calls_out_list = [ e for e in cursor ]
print(f"Processing {len(indir_calls_out_list)} Indirect Out edges")

for old_edge in indir_calls_out_list:
    src_node = old_edge['_from']
    target_node = old_edge['_to']

    new_edge_key = get_hashed_str(f"{src_node}__{target_node}__swap")

    DELETE_STAT=f"""REMOVE @old_edge IN indirect_calls_out OPTIONS {{waitForSync: true}}
    """
    global_db.aql.execute(DELETE_STAT, bind_vars={'old_edge':old_edge['_key']})
    
    '''
    INSERT_STAT = f"""INSERT {{
                        '_key': @edge_key,
                        '_from': @source,
                        '_to': @target,
                    }} INTO indirect_calls_out_swap OPTIONS {{waitForSync: true, overwriteMode: 'ignore'}}"""
    global_db.aql.execute(INSERT_STAT,
            bind_vars={
                'edge_key': new_edge_key,
                'source': src_node,
                'target': target_node
                })
    '''
