import os
from collections import defaultdict
import json
import csv

""" Create a mapping from elf file names to deb packages. Useful to resolve elfs top debs when creating the
ldd knowledge graph
"""
ldd_csv_file_list = []
with open("../data/processed_libs_csv_jul18.txt", "r") as f:
    for line in f.readlines():
        ldd_csv_file_list.append(line.strip().rstrip())

elf_deb_dict = defaultdict(list)

exe_count = 0
for elf_csv_path in ldd_csv_file_list:
    deb_name = ""
    with open(elf_csv_path, "r") as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=",")
        for row in csv_reader:
            if row[0] == "DEB_NAME":
                deb_name = row[1]
            # Always rely on SONAMES extracted from the readelf header
            if row[0] == "SONAME":
                if not deb_name in elf_deb_dict[row[1]]:
                    elf_deb_dict[row[1]].append(deb_name)
                    exe_count += 1

with open("../data/elf_to_deb_map.json", "w") as json_file:
    json.dump(elf_deb_dict, json_file, indent=4)
