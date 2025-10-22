import multiprocessing
import itertools
import subprocess
import shlex
import os
import json

def get_bin_packs(deb_pack):
    global shared_json
    print(f"Starting {deb_pack}")
    binary_debs = []
    command = f'apt-rdepends -r {deb_pack}'

    out = subprocess.run(shlex.split(command), capture_output=True)
    rdepends_list = []

    if out.returncode:
        print(f"Error: {deb_pack}")
        shared_json.update({deb_pack:[]})
        return
    else:
        output = out.stdout.decode()
        for line in output.splitlines():
            line = line.strip().rstrip()
            if line.startswith("Reverse Depends: "):
                continue
            rdepends_list.append(line.split(" ")[0])
    shared_json.update({deb_pack:rdepends_list})

    print(f"Done {deb_pack}")

def initializer(pool_bin_deb_json):
    global shared_json
    shared_json = pool_bin_deb_json

def main():
    apt_src_list = []
    with open('/home/potential_vuln_deb_list.txt', "r") as f:
        for line in f.readlines():
            apt_src_list.append(line.strip().rstrip())
    
    manager = multiprocessing.Manager()
    shared_json = manager.dict()
    pool = multiprocessing.Pool(initializer=initializer, initargs=(shared_json,), processes=44)
    pool.map(get_bin_packs, apt_src_list)

    with open("/home/vuln_debs_rdepends.json", "w") as f:
        json.dump(shared_json._getvalue(), f, indent=4)


if __name__=="__main__":
    main()
