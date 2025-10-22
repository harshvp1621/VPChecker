import multiprocessing
import itertools
import subprocess
import shlex
import os
import json

def get_bin_packs(src_pack):
    global shared_json
    print(f"Starting {src_pack}")
    binary_debs = []
    command = f'apt-cache showsrc {src_pack}'

    out = subprocess.run(shlex.split(command), capture_output=True)

    if out.returncode:
        print(f"Error: {src_pack}")
        shared_json.update({src_pack:[]})
        return
    else:
        output = out.stdout.decode()
        for line in output.splitlines():
            line = line.strip().rstrip()
            if line.startswith("Binary: "):
                pack_list = line.split("Binary: ")[1].split(",")
                for pack in pack_list:
                    pack = pack.strip()
                    if pack not in binary_debs:
                        binary_debs.append(pack)

    shared_json.update({src_pack:binary_debs})
    print(f"Done {src_pack}")

def initializer(pool_bin_deb_json):
    global shared_json
    shared_json = pool_bin_deb_json

def main():
    apt_src_list = []
    with open('/home/vuln_apt_sources.txt', "r") as f:
        for line in f.readlines():
            apt_src_list.append(line.strip().rstrip())
    
    manager = multiprocessing.Manager()
    shared_json = manager.dict()
    pool = multiprocessing.Pool(initializer=initializer, initargs=(shared_json,), processes=32)
    pool.map(get_bin_packs, apt_src_list)

    with open("/home/apt_src_deb_maps.json", "w") as f:
        json.dump(shared_json._getvalue(), f, indent=4)


if __name__=="__main__":
    main()
