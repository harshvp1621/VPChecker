import json
import copy
from bs4 import BeautifulSoup
import requests
import traceback
import multiprocessing
import itertools
import os

CUTOFF_YEAR = 2022

# Clone this submodule
cve_v5_repo = "./cvelistV5/cves"

# This is the complete debian security tracker feed downloaded from
# https://security-tracker.debian.org/tracker/data/json/
deb_sec_json = json.load(open("./notebooks/data/debian_sec_tracker_06232024.json", "r"))

def get_urls_from_debsec(cve_id):
    cve_url = f"https://security-tracker.debian.org/tracker/{cve_id}"
    try:
        html_content = requests.get(cve_url).text
        soup = BeautifulSoup(html_content, 'html.parser')

        # We are interested in parsing all links under the Notes header
        notes_h = soup.find('h2', string='Notes')
        if notes_h is None:
            return []
        notes_section = notes_h.find_next_sibling('pre')

        links = []
        for a in notes_section.find_all('a', href=True):
            if a.previous_sibling:
                if "introduced by" in a.previous_sibling.text.lower():
                    with open('Introduced_By_CVEs.txt', 'a+') as f:
                        f.write(f"{cve_id} {a['href']}\n")
                    continue
            links.append(a['href'])

        return links
    except Exception as e:
        print(traceback.format_exc())
        return []

def merge_cve_recs(cve):
    global shared_cve_dict
    global cve_2_record_map

    cve_record = {"references":[]}

    deb_sec_urls = get_urls_from_debsec(cve)
    for deb_sec_url in deb_sec_urls:
        cve_record["references"].append(
            {
                "url": deb_sec_url,
                "name": deb_sec_url,
                "refsource": "DEB_SEC_TRACKER",
                "tags": [],
            }
        )
    
    try:
        cve_v5_file = json.load(open(f"{cve_2_record_map[cve]}", "r"))
    except Exception:
        shared_cve_dict.update({cve:cve_record})
        return
    
    # Updated URLs from CVE V5 Feed
    for container, info in cve_v5_file["containers"].items():
        # There can be more than one containers - CNA, ADP
        # Take references from both
        try:
            cve_record["references"] += info["references"]
        except Exception as e:
            cve_record["references"].append(
                    {
                        "url": "UNAVAILABLE",
                        "refsource": "CVE_V5"
            })

    print(f"Done {cve}")

    shared_cve_dict.update({cve:cve_record})

def create_recent_json(year, shared_cve_dict):
    """ year - Will extract CVEs >= the year
    """
    deb_sec_json_recent = copy.deepcopy(deb_sec_json)

    for src_package, cve_dets in deb_sec_json.items():
        for cve_id in cve_dets:
            tokens = cve_id.split("-")
            cve_str = tokens[0]
            cve_year = tokens[1]
            if cve_str != "CVE":
                deb_sec_json_recent[src_package].pop(cve_id)
                continue

            if int(cve_year) < year:
                deb_sec_json_recent[src_package].pop(cve_id)
                continue
            deb_sec_json_recent[src_package][cve_id]["references"] = copy.deepcopy(shared_cve_dict[cve_id]["references"])

    with open(f"./notebooks/data/deb_sec_tracker_merged_{year}.json", "w") as f:
        json.dump(deb_sec_json_recent, f, indent=4)

def initializer(pool_cve_2_record_map, pool_cve_dict):
    global cve_2_record_map
    cve_2_record_map = pool_cve_2_record_map

    global shared_cve_dict
    shared_cve_dict = pool_cve_dict

def main():
    cve_2_record_map = {}
    for top_dir, sub_dirs, files in os.walk(cve_v5_repo, topdown=False):
        for file_name in files:
            full_file_path = os.path.join(top_dir, file_name)
            # Ignore Symlinks
            if os.path.islink(full_file_path):
                continue
            cve_id = full_file_path.split("/")[-1].split(".json")[0]
            cve_2_record_map[cve_id] = full_file_path

    debian_cve_list = []
    for pack, dets in deb_sec_json.items():
        for cve in dets:
            if int(cve.split("-")[1]) < CUTOFF_YEAR:
                continue
            if cve not in debian_cve_list:
                debian_cve_list.append(cve)
    print(f"Processing {len(debian_cve_list)} CVEs")
    manager = multiprocessing.Manager()
    shared_cve_dict = manager.dict()

    pool = multiprocessing.Pool(initializer=initializer, initargs=(cve_2_record_map, shared_cve_dict), processes=48)
    pool.map(merge_cve_recs, debian_cve_list, chunksize=250)

    with open(f"./notebooks/data/{str(CUTOFF_YEAR)}_cve_records.json", "w") as f:
        json.dump(shared_cve_dict._getvalue(), f, indent=4)

    create_recent_json(CUTOFF_YEAR, shared_cve_dict._getvalue())


if __name__=="__main__":
    main()
