import os
import argparse
import sys
import csv
import multiprocessing
import subprocess
import shlex
from pathlib import Path

def get_elf_arch_class(file_path):
    cmd = f"readelf -h {file_path}"
    try:
        output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.DEVNULL).decode('utf-8')
        for line in output.splitlines():
            tokens = line.strip().split(":")
            if tokens[0] == "Class":
                return tokens[1].strip()
    except:
        return None
    return None

def get_elf_machine(file_path):
    cmd = f"readelf -h {file_path}"
    try:
        output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.DEVNULL).decode('utf-8')
        for line in output.splitlines():
            tokens = line.strip().split(":")
            if tokens[0] == "Machine":
                arch_str = tokens[1].strip()
                if ("/" in arch_str): # Some IBM arch has a '/' in name
                    arch_str = arch_str.replace("/", "__")
                return arch_str.replace(" ", "_")
    except:
        return None
    return None

def check_if_shared_obj(file_path):
    cmd = f"readelf -h {file_path}"
    REF_STRING="DYN (Shared object file)"
    try:
        output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.DEVNULL).decode('utf-8')
        for line in output.splitlines():
            tokens = line.strip().split(":")
            if tokens[0] == "Type" and\
                    tokens[1].strip() == REF_STRING:
                        return True
        return False
    except:
        return False
    return False

def get_elf_dyn(file_path):
    """ Return the needed SO files and SONAME if any
    """
    arch = get_elf_arch_class(file_path)
    dyn_info = {}
    dyn_info["ARCH"] = arch
    dyn_info["MACH"] = get_elf_machine(file_path)
    dyn_info["TYPE"] = ""
    dyn_info["NEEDED"] = []
    dyn_info["SONAME"] = ""

    if check_if_shared_obj(file_path):
        dyn_info["TYPE"] = "SHARED"
    else:
        dyn_info["TYPE"] = "EXEC"

    cmd = f"readelf -d {file_path}"
    try:
        out = subprocess.check_output(shlex.split(cmd), stderr=subprocess.DEVNULL).decode()
        for line in out.splitlines():
            tokens = line.strip().split("  ")
            cols = tokens[0].split(" ")
            if len(cols) < 2:
                continue
            if cols[1] == "(NEEDED)":
                needed = tokens[-1].strip().split(":")[1].strip().strip('[').strip(']')
                dyn_info["NEEDED"].append(f'{needed}')
            elif cols[1] == "(SONAME)":
                soname = tokens[-1].strip().split(":")[1].strip().strip('[').strip(']')
                dyn_info["SONAME"] = f'{soname}'
        if dyn_info["SONAME"] == "":
            dyn_info["SONAME"] = os.path.basename(f'{file_path}')
    except Exception as e:
        print(e)
        return None
    return dyn_info

def run_tasks(full_path):
    try:
        print(f"Processing {full_path}")
        if os.path.isdir(full_path):
            return
        if os.path.islink(full_path):
            print(f"Resolving link {full_path}")
            full_path = str(Path(full_path).resolve())

        dyn_info = get_elf_dyn(full_path)
        if dyn_info is None:
            print(f"Skipping {full_path}, Not a Dyn Exec")
            return
        deb_name = full_path.split("/")[-2]
        arch = dyn_info["ARCH"]
        mach = dyn_info["MACH"]
        with open(f"{full_path}_{deb_name}_{arch}_elf_info.csv", "w") as f:
            writer = csv.writer(f)
            writer.writerow(["DEB_NAME", deb_name])
            writer.writerow(["ARCH", dyn_info["ARCH"]])
            writer.writerow(["MACH", dyn_info["MACH"]])
            writer.writerow(["TYPE", dyn_info["TYPE"]])
            writer.writerow(["SONAME", dyn_info["SONAME"]])
            for needed in dyn_info["NEEDED"]:
                writer.writerow(["NEEDED", needed])
    except Exception as e:
        print(e)
        return

def main():
    file_list = []
    with open("../data/processed_libs_jul18.txt", "r") as file:
        file_list = [ line.rstrip() for line in file ]
    print(f"Found {len(file_list)} files")
    pool = multiprocessing.Pool(processes=48)
    pool.map(run_tasks, file_list)
    print("Done")

if __name__=="__main__":
    main()
