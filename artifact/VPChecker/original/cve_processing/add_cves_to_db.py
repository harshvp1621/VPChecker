import os
import traceback
import csv
from hashlib import sha256
from collections import defaultdict
from colorama import Fore, Style
import copy
import multiprocessing

from arango import ArangoClient

CVE_CSV_FILE="../../notebooks/data/cve_funcs_debs_elfs_found.csv"
# Read the CSV for CVES
# Create nodes for CVEs
# Connect to functions based on their "name" field and not the "_key"
# to take care of name mangling

# CSV Node properties:
# CVE ID
# ELF Binary
# Package Name
# Status

# CVE Edges:
# CVE affects func
# CVE related CVE

def get_hashed_str(input_str):
    return sha256(input_str.encode()).hexdigest()

FUNC_CALL_GRAPH_NAME = "call_graph"
ELF_DEP_GRAPH_NAME = "ldd_graph"
FUNC_NODE_COLL_NAME = "functions"
ELF_NODE_COLL_NAME = "elf_bins"

CVE_NODE_COLL_NAME = "cves"
CVE_AFFECTS_EDGE_COLL_NAME = "cve_affects"
CVE_RELATED_EDGE_COLL_NAME = "cve_relates"

def add_cve_node(cve_tuple):
    global FUNC_CALL_GRAPH_NAME
    global CVE_NODE_COLL_NAME
    global CVE_AFFECTS_EDGE_COLL_NAME
    global db

    tokens = cve_tuple.split(",")
    cve = tokens[0]
    deb_name = tokens[1]
    elf_name = tokens[2]
    func_key = tokens[3]
    cve_status = tokens[4]

    print(f"Processing {cve_tuple}")

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

    # Add CVE Node
    if not check_doc_present(CVE_NODE_COLL_NAME, f'{CVE_NODE_COLL_NAME}/{cve}'):
        try:
            INSERT_STAT = f""" INSERT {{
                '_key': @cve_id,
                'elf_list': @elf_list,
                'deb_list': @deb_list,
                'status': @cve_status
            }} INTO {CVE_NODE_COLL_NAME} OPTIONS {{ overwriteMode: 'ignore', waitForSync: true }}
            """
            db.aql.execute(INSERT_STAT,
                    bind_vars={
                        "cve_id": cve,
                        "elf_list":[elf_name],
                        "deb_list":[deb_name],
                        "cve_status":cve_status
                        })
        except Exception as e:
            print(f"Error inserting tuple {cve_tuple}")
            print(e)
            return
    else:
        cve_node = get_doc(CVE_NODE_COLL_NAME, f"{CVE_NODE_COLL_NAME}/{cve}")
        curr_node_elf_list = copy.deepcopy(cve_node['elf_list'])
        if elf_name not in curr_node_elf_list:
            curr_node_elf_list.append(elf_name)

        curr_node_deb_list = copy.deepcopy(cve_node['deb_list'])
        if deb_name not in curr_node_deb_list:
            curr_node_deb_list.append(deb_name)

        UPDATE_STAT = f""" UPDATE {{
            '_key': @cve_id,
            'elf_list': @elf_list,
            'deb_list': @deb_list
        }} IN {CVE_NODE_COLL_NAME}
        """
        db.aql.execute(UPDATE_STAT,
                bind_vars={
                    "cve_id": cve,
                    "elf_list": curr_node_elf_list,
                    "deb_list": curr_node_deb_list,
                    })

    # Add CVE Edge
    cve_affects_edge_key = get_hashed_str(f"{cve}_{func_key}")
    if not check_doc_present(CVE_AFFECTS_EDGE_COLL_NAME, f"{CVE_AFFECTS_EDGE_COLL_NAME}/{cve_affects_edge_key}"):
        try:
            INSERT_STAT = f""" INSERT {{
                '_key': @cve_edge_key,
                '_from': @source,
                '_to': @target
            }} INTO {CVE_AFFECTS_EDGE_COLL_NAME} OPTIONS {{ overwriteMode: 'ignore', waitForSync: true }}
            """
            db.aql.execute(INSERT_STAT,
                    bind_vars={
                        "cve_edge_key": cve_affects_edge_key,
                        "source": f"{CVE_NODE_COLL_NAME}/{cve}",
                        "target": f"functions/{func_key}"
                        })
        except Exception as e:
            print(f"Error inserting edge from {cve} -> {func_key}")
            print(e)
    print("Done")


def get_arango_connection():
    client = ArangoClient(hosts='http://localhost:8529')
    global db
    db = client.db('sysfilter', username='root', password='root')

    global arango_call_graph
    arango_call_graph = db.graph('call_graph')
    
def main():
    cve_funcs_tuples = []
    with open(CVE_CSV_FILE, "r") as f:
        for line in f.readlines():
            cve_funcs_tuples.append(line.strip())

    pool = multiprocessing.Pool(initializer=get_arango_connection, processes=48)

    pool.map(add_cve_node, cve_funcs_tuples)

if __name__=="__main__":
    main()
