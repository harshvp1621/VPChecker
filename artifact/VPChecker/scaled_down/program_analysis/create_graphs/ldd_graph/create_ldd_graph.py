import csv
import os
import argparse
from arango import ArangoClient
import sys
import json

client = ArangoClient(hosts='http://localhost:8529')
db = client.db('sysfilter_scaled_down', username='root', password='root')
ldd_graph = db.graph('ldd_graph')
elf_vertex_collection = ldd_graph.vertex_collection('elf_bins')
edge_collection = ldd_graph.edge_collection('depends_on')

ELF_64 = "ELF64"
AMD64 = "Advanced_Micro_Devices_X86-64"
elf_to_deb_map = json.load(open("../../data/elf_to_deb_map.json", "r"))

def sanitize_deb_name(name):
    if '~' in name:
        name = name.replace('~', '%7E')
    if '+' in name:
        name = name.replace('+', '%2B')
    return name

def parse_args(argv):
    parser = argparse.ArgumentParser(description="Create LDD Graph")
    parser.add_argument("-p",
                        "--path",
                        action="store",
                        required=True,
                        help="Parse CSVs in this directory")
    args = parser.parse_args(argv)
    return args

def get_csvs(top_path):
    csv_list = []
    for top_dir, sub_dirs, files in os.walk(f"{top_path}", topdown=False):
        for file_name in files:
            full_file_path = os.path.join(top_dir, file_name)
            if file_name.endswith(".csv"):
                csv_list.append(full_file_path)
    return csv_list

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


def main():
    args = parse_args(sys.argv[1:])
    csv_path = args.path

    csv_list = get_csvs(csv_path)
    for csv_file in csv_list:
        # Read CSV file
        with open(csv_file, 'r') as f:
            #print(f"Parsing {csv_file}")
            csv_reader = csv.reader(f, delimiter=',')
            exec_type = ""
            deb_name = ""
            arch = ""
            mach = ""
            soname = ""
            needed = ""
            for row in csv_reader:
                if row[0] == "ARCH":
                    arch = row[1]
                    if arch != ELF_64:
                        break
                if row[0] == "MACH":
                    mach = row[1]
                    if("/" in mach):
                        mach = arch.replace("/", "__")
                    if mach != AMD64:
                        break
                if row[0] == "SONAME": # Also valid for binary executables
                    soname = row[1]
                    if("/" in soname):
                        soname = soname.replace("/", "__")
                    if("[" in soname):
                        soname = soname.replace("[", "RIGHT_SQ_BRACKET")
                if row[0] == "TYPE":
                    exec_type = row[1]
                if row[0] == "DEB_NAME":
                    deb_name = row[1]

                soname_key = f"{soname}@{sanitize_deb_name(deb_name)}"
                if soname != "":
                    if not check_doc_present('elf_bins', f'elf_bins/{soname_key}'):
                        elf_vertex_collection.insert({
                            "_key": soname_key,
                            "arch": arch,
                            "type": exec_type,
                            "deb_name": sanitize_deb_name(deb_name),
                        })

                if row[0] == "NEEDED":
                    needed = row[1]
                    if needed not in elf_to_deb_map:
                        print(f"Deb not found for {needed} when parsing deps of {soname}")
                        continue
                    needed_deb_list = elf_to_deb_map[needed]
                    for d in needed_deb_list:
                        # Create a vertex for library
                        dep_key = f"{needed}@{sanitize_deb_name(d)}"
                        if not check_doc_present('elf_bins', f'elf_bins/{dep_key}'):
                            elf_vertex_collection.insert({
                                    "_key": dep_key,
                                    "arch": arch,
                                    "type": "SHARED",
                                    "deb_name": sanitize_deb_name(d),
                                })
                        # Create edge betweeen ELF binary and library
                        if not check_doc_present('depends_on', f"depends_on/{soname_key}_{dep_key}"):
                            edge_collection.insert({
                                    "_key": f"{soname_key}_{dep_key}",
                                    "_from": f"elf_bins/{soname_key}",
                                    "_to": f"elf_bins/{dep_key}"
                                })

if __name__=="__main__":
    main()
