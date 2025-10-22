import os
import subprocess
import json
import requests
import re
from collections import defaultdict
import shlex
import argparse
from bs4 import BeautifulSoup
import traceback

from urllib.parse import unquote, urlparse
from common import patch_utils

ROOT_PATH = os.getcwd()
CLONE_PATH = os.path.join(ROOT_PATH, "clones")
if not os.path.exists(path=CLONE_PATH):
    os.makedirs(CLONE_PATH)

def read_json_obj(json_path):
    json_data = None
    for json_file in os.listdir(json_path):
        if not json_file.endswith(".cves.json"):
            # Do not process non JSON files
            continue
        # Open JSON file
        with open(os.path.join(json_path, json_file), 'r') as file:
            json_data = json.load(file)
            # Iterate through each Package
            for package, cve_data in json_data.items():
                # Iterate through each CVE
                patch_utils.get_commit_urls(cve_data)
                if package == "curl":
                    patch_utils.get_curl_commit_urls(cve_data)

    return json_data

def find_vulnerable_functions(apt_src_name, json_data, json_dir):
    vulnerable_libraries = defaultdict(dict)
    for package, cve_data in json_data.items():
        for cve_id in cve_data:
            print(f"Processing {cve_id}...")
            if "references" not in cve_data[cve_id]:
                print(f"{cve_id}: No references section")
                continue

            for url_dict in cve_data[cve_id]["references"]:
                print(f"\nProcessing {url_dict['url']}")
                if "diff_url" not in url_dict:
                    print(f"{cve_id}: {url_dict['url']} is not a commit diff url")
                    continue
                url = patch_utils.get_redirected_url(url_dict["diff_url"])
                current_library = patch_utils.get_package_name(url)
                if current_library is None:
                    print(f"{cve_id}: Unable to infer current lib name from {url}")
                    continue
                elif apt_src_name not in current_library:
                    print(f"{cve_id}: Cloning external library {current_library} at {url}")
                if cve_id not in vulnerable_libraries[current_library]:
                    vulnerable_libraries[current_library][cve_id] = {}

                if url not in vulnerable_libraries[current_library][cve_id]:
                    vulnerable_libraries[current_library][cve_id][url] = []
                else:
                    # This URL was already processed
                    continue

                try:
                    print(f"Fetching diff URL {url}")
                    res_diff_url = requests.get(url)
                except:
                    print(f"Exception while fetching diff URL {url}")
                    print(str(traceback.format_exc()))
                    continue
                if res_diff_url.status_code != 200:
                    print(f"{cve_id}: Content Fetching Error {res_diff_url.status_code} {url}")
                    continue

                diffs = res_diff_url.text.split('diff --git')
                clone_dir = patch_utils.clone_repo(url, CLONE_PATH)
                if clone_dir is None:
                    print(f"{cve_id}: Unable to clone url {url}")
                    continue

                for diff in diffs:
                    diff_lines = diff.split('\n')

                    os.chdir(clone_dir)

                    if not diff_lines[0].strip().rstrip().startswith("a/"):
                        continue

                    # index eb3c41577aa..2d5478621b8 100644 -> eb3c41577aa
                    orig_file_index = diff_lines[1].split(' ')[1].split('..')[0]
                    #  a/elf/dl-load.c b/elf/dl-load.c -> elf/dl-load.c
                    changed_file_path = diff_lines[0].split(' ')[1][2:]

                    changed_file_info = {
                        'file': changed_file_path,
                        'vulnerable_functions': []
                    }

                    if not (
                        changed_file_path.endswith('.c') or
                        changed_file_path.endswith('.h') or
                        changed_file_path.endswith('.cpp') or
                        changed_file_path.endswith('.hpp') or
                        changed_file_path.endswith('.cc') or
                        changed_file_path.endswith('.cxx') or
                        changed_file_path.endswith('.cxx') or
                        changed_file_path.endswith('.hh')):
                        vulnerable_libraries[current_library][cve_id][url].append(changed_file_info)
                        continue

                    orig_source_path = os.path.join(clone_dir, f"orig.{changed_file_path.replace('/', '.')}")
                    # print(f"Orig source path {orig_source_path}")
                    with open(os.path.join(clone_dir, orig_source_path), 'w') as orig_source:
                        try:
                            # Get the old source file
                            subprocess.run(['git', 'show', orig_file_index], stdout=orig_source, stderr=subprocess.DEVNULL)
                        except Exception as e:
                            print(str(traceback.format_exc()))
                            continue

                        # Get the line numbers of each change
                        line_ranges = [(int(start), int(start) + int(length)) for start, length in re.findall(r'@@ -(\d+),(\d+) \+\d+,\d+ @@', diff)]
                        # print(line_ranges)
                        # Run ctags to get information about each function in the old source file
                        # https://docs.ctags.io/en/latest/man/ctags.1.html#extension-fields
                        # ctags_proc = subprocess.run(['ctags', '--fields=+Stne-f', '-o', '-', '--sort=no', '--c-kinds=f', orig_source_path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                        ctags_command = f'ctags --fields=+Stne-f -o - --sort=no --c-kinds=f {orig_source_path}'
                        ctags_proc = subprocess.run(shlex.split(ctags_command), stdout=subprocess.PIPE)
                        ctags_lines = ctags_proc.stdout.decode('utf-8').split('\n')

                        for ctags_line in ctags_lines:
                            if ctags_line.strip() == "":
                                # print(f"{cve_id}: Got empty line from ctags")
                                continue
                            # print(ctags_line)
                            ctags_fields = ctags_line.split('\t')
                            if len(ctags_fields) == 1:
                                print("Some ctags issue")
                                print(ctags_command)
                                print(ctags_line)
                                exit()
                                continue

                            function_info = {
                                'name': ctags_fields[0],
                                'parameters': None,
                                'return_type': None,
                                'start_line': None,
                                'end_line': None,
                            }

                            # Not all of these fields are always defined by ctags
                            # Must check if the field is defined before accessing it
                            for i in range(4, len(ctags_fields)):
                                ctags_field = ctags_fields[i].split(':')
                                match ctags_field[0]:
                                    case 'line':
                                        function_info['start_line'] = int(ctags_field[1])
                                    case 'end':
                                        function_info['end_line'] = int(ctags_field[1])
                                    case 'signature':
                                        function_info['parameters'] = ctags_field[1]
                                    case 'typeref':
                                        function_info['return_type'] = ':'.join(ctags_field[1:])
                                    case _:
                                        continue

                            if function_info['start_line'] == None or function_info['end_line'] == None:
                                continue
                            # Determine if function is in the diff
                            for start, end in line_ranges:
                                # print(f"Function {function_info['name']} start {function_info['start_line']} {start}, end: {function_info['end_line']} {end}")
                                # The boundary check is heuristically determined. Since diff hunks can sometimes have spaces/extra lines
                                # before and after the actual change, it's possible that the function boundaries do not necessarily fall within the specified ranges. Eg. CVE-2017-3735
                                if function_info['start_line'] <= (start+1) and function_info['end_line'] >= (end-3):
                                    # print(ctags_fields)
                                    # print(f"Function start {function_info['start_line']} {start}, end: {function_info['end_line']} {end}")
                                    changed_file_info['vulnerable_functions'].append(function_info)
                                    break
                            # print("===========================================")

                    # Remove the old source file
                    os.remove(orig_source_path)

                    # Update the vulnerable library dictionary
                    if len(changed_file_info['vulnerable_functions']) > 0:
                        vulnerable_libraries[current_library][cve_id][url].append(changed_file_info)
                    else:
                        print(f"{cve_id}: No Info for file {changed_file_info['file']}")
                url_dict.update({
                    "patch_details": vulnerable_libraries[current_library][cve_id][url]
                })

                # Remove any libraries that have no files with vulnerable functions
                # if len(vulnerable_libraries[current_library][cve_id]) == 0:
                #     print(f"{cve_id}: No functions extracted for {current_library}")
                #     vulnerable_libraries.pop(current_library)

            os.chdir(ROOT_PATH)
            if not os.path.exists(f"{json_dir}/cves"):
                os.mkdir(f"{json_dir}/cves")
            with open(f"{json_dir}/cves/{cve_id}.json", "w") as f:
                json.dump({cve_id: cve_data[cve_id]}, f, indent=4)
    return vulnerable_libraries

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Script to parse CVE JSON in the input path, download repos and patches and output vulnerable function jsons")
    parser.add_argument("--json_dir", '-j', type=str, required=True, help='Directory containing CVE JSON')
    parser.add_argument("--apt_src", '-a', type=str, required=True, help='APT Source Name that has the CVEs')
    args = parser.parse_args()

    json_data = read_json_obj(args.json_dir)
    vulnerable_libraries = find_vulnerable_functions(args.apt_src, json_data, args.json_dir)
    with open(f'{args.json_dir}/{args.apt_src}.funcs.json', 'w') as json_output:
        json.dump(vulnerable_libraries, fp=json_output, indent=4)
