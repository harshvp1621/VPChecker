import os
import subprocess
import multiprocessing
import json
import shlex

ROOT_PATH = os.getcwd()

# This JSON is "merged" i.e. it contains CVE references that were merged from the CVE Org Feed and the Debian Sec Tracker Feed
deb_sec_json_recent = json.load(open(f"{ROOT_PATH}/notebooks/data/deb_sec_tracker_merged_2022.json", "r"))

def create_apt_src_cve_json(apt_src_name):
    target_path = f"{ROOT_PATH}/cve_json_feed/{apt_src_name}"
    if not os.path.exists(target_path):
        os.mkdir(target_path)
    with open(f"{target_path}/{apt_src_name}.cves.json", "w") as f:
        json.dump({apt_src_name: deb_sec_json_recent[apt_src_name]}, f, indent=4)

def run_task(apt_src):
    if apt_src == 'linux':
        return
    print(f"Processing {apt_src}")
    create_apt_src_cve_json(apt_src)
    with open(f"{ROOT_PATH}/cve_json_feed/{apt_src}/{apt_src}.out", "w") as file_out:
        subprocess.run(shlex.split(f"python3 {ROOT_PATH}/json_to_func.py -j {ROOT_PATH}/cve_json_feed/{apt_src} -a {apt_src}"), stdout=file_out, stderr=file_out)
    print(f"Done {apt_src}")

def initializer(pool_apt_source_list):
    global apt_src_list
    apt_src_list = pool_apt_source_list

def main():
    apt_src_list = []
    with open(f"{ROOT_PATH}/notebooks/data/vuln_apt_sources.txt", "r") as f:
        for line in f.readlines():
            apt_src_list.append(line.strip())
    print(f"Processing {len(apt_src_list)} apt sources")
    pool = multiprocessing.Pool(initializer=initializer, initargs=(apt_src_list, ), processes=1)
    pool.map(run_task, apt_src_list)

if __name__=="__main__":
    main()
