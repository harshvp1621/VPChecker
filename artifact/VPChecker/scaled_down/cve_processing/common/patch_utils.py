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

## CONFIGURE ##
git_list 	= [
	"github.com",
	"gitlab", # Requires authentication only when accessing closed projects
    "gitweb",
    "git.",
    "cgit.",
    "/git/",
    "/cgit/",
    "/git?"
]

# If any of the below tokens are present in git url, then exclude that url
git_exclude_list = [
    "/issues/", # Exclude links to github issues
    "/advisories/",
    "/blob/",
    "/tags",
    "/releases",
]
## END CONFIGURE ##

def get_redirected_url(url):
    ''' Returns the redirected URL in case of redirection, otherwise return regular URL
    '''
    try:
        response = requests.get(url, allow_redirects=True)
        if response.history:
            for resp in response.history:
                if resp.status_code in [301, 302]:
                    return response.url
        # Return the same URL if there was not redirect
        return url
    except requests.RequestException as e:
        print(f"Error while trying to get redirect URL for {url}: {e}")
        return None

def get_urls_from_debsec(cve_id):
    cve_url = f"https://security-tracker.debian.org/tracker/{cve_id}"
    try:
        html_content = requests.get(get_redirected_url(cve_url)).text
        soup = BeautifulSoup(html_content, 'html.parser')

        # We are interested in parsing all links under the Notes header
        notes_section = soup.find('h2', string='Notes').find_next_sibling('pre')

        links = [a['href'] for a in notes_section.find_all('a', href=True)]
        return links
    except Exception as e:
        print(str(traceback.format_exc()))
        return []

def get_package_name(url):
    url_obj = urlparse(url)

    if 'github.com' in url_obj.netloc:
        path = url_obj.path.split('/')
        return f'{path[1]}/{path[2]}'

    elif 'gitlab' in url_obj.netloc:
        # Gitlab URLs have dashes to differentiate between endpoints and projects
        # Ref: https://gitlab.com/gitlab-org/gitlab/-/issues/273668
        path = url_obj.path.split('/-')
        return path[0]

    ###### Gitweb hosts ######
    elif 'gitweb' in url_obj.path or 'p=' in url_obj.query:
        # Some gitweb hosts don't have /gitweb/ in the path, but all seem to have p= in the query
        query = unquote(url_obj.query).split(';')
        for param in query:
            if param.startswith('p='):
                name = param.split('p=')[1][:-4]
                return f'gitweb/{name}'

        # Those that don't have a query ?p=
        return f"{url.split('gitweb/')[1].split('/')[0]}"
    ###### Raw files from github pull requests ######
    elif 'githubusercontent' in url_obj.netloc:
        # Handling: https://patch-diff.githubusercontent.com/raw/nghttp2/nghttp2/pull/1961.diff
        path = url_obj.path.split('/raw/')
        return path[1].split("/pull/")[0]
    ###### cgit hosts ######
    elif 'cgit.' in url_obj.netloc:
        path = url_obj.path.split('/')
        if path[2] == 'commit':
            return path[1]
        else:
            return path[1] + '/' + path[2]

    elif 'git.' in url_obj.netloc:
        path = url_obj.path.split('/')
        for p in path:
            if p.endswith('.git'):
                name = p[:-4]
                return name

    return None

def get_diff_url(url):
    url_obj = urlparse(url)

    # Sometimes the diff is directly mentioned
    if url.endswith(".diff") or "a=commitdiff_plain" in url:
        return url

    if 'github.com' in url_obj.netloc:
        if '/commit/' in url_obj.path:
            return url + '.diff'
        elif '/pull/' in url_obj.path:
            return url + '.diff'
        elif '/releases/' in url_obj.path:
            commit_url = get_commit_url_from_release(url)
            if commit_url is not None:
                return commit_url + '.diff'

    elif 'gitlab' in url_obj.netloc:
        if '/commit/' in url:
            return url + '.diff'
        if '/merge_requests/' in url:
            return url + '.diff'

    ###### Gitweb hosts ######
    elif 'gitweb' in url_obj.path or 'p=' in url_obj.query:
        # Some gitweb hosts don't have /gitweb/ in the path, but all seem to have p= in the query
        if 'a=commitdiff' in url:
            return url.replace('a=commitdiff', 'a=commitdiff_plain')
        elif 'a=commit' in url:
            return url.replace('a=commit', 'a=commitdiff_plain')
        elif 'a=blobdiff' in url:
            return url.replace('a=blobdiff', 'a=blobdiff_plain')
        else: # no existing action in url
            # gitweb links that include a file must use the blobdiff_plain action instead
            if 'f=' in url:
                return url + ';a=blobdiff_plain'
            elif "/commit/" in url:
                return url.replace('/commit/', 'commitdiff_plain')
            else:
                return url + ';a=commitdiff_plain'

    ###### cgit hosts ######
    elif 'cgit.' in url_obj.netloc:
        return url.replace('/commit/', '/patch/')

    elif 'git.' in url_obj.netloc:
        return url.replace('/commit/', '/patch/')

    return None

def repo_exists(repo_url):
    # Check if the repo is accessible
    print(f"Checking repo URL {repo_url}")
    ls_remote = f'git ls-remote -h {repo_url}'
    result = subprocess.run(shlex.split(ls_remote), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        print("Failed")
        return False
    print("Successful")
    return True

path_variations = [
    '/',
    '/git/',
    '/projects/',
]
protocol_variations = [
    'https',
    'git',
]
checked_repo_paths = {} # Cache for checked repo paths
def check_repo_paths(package_name, url_obj):
    if package_name in checked_repo_paths and url_obj.netloc in checked_repo_paths[package_name]:
        return checked_repo_paths[package_name][url_obj.netloc]
    elif package_name not in checked_repo_paths:
        checked_repo_paths[package_name] = {}

    for path_variation in path_variations:
        for protocol_variation in protocol_variations:
            repo_url = get_redirected_url(f"{protocol_variation}://{url_obj.netloc}{path_variation}{package_name}.git")
            if repo_exists(repo_url):
                checked_repo_paths[package_name][url_obj.netloc] = repo_url
                print(f"Found repo URL {repo_url}")
                return repo_url

            # Check without package_name.git
            repo_url = get_redirected_url(f"{protocol_variation}://{url_obj.netloc}{path_variation}{package_name}")
            if repo_exists(repo_url):
                checked_repo_paths[package_name][url_obj.netloc] = repo_url
                print(f"Found repo URL {repo_url}")
                return repo_url

    checked_repo_paths[package_name][url_obj.netloc] = None
    return None

def clone_repo(url, clone_path):
    # We assume that the url passed here is a valid git commit diff URL
    package_name = get_package_name(url)
    if package_name is None:
        return None

    clone_dir = os.path.join(clone_path, package_name.replace('/', '##').replace('gitweb##', ''))
    if os.path.exists(clone_dir):
        return clone_dir

    url_obj = urlparse(url)

    if 'github.com' in url_obj.netloc:
        repo_url = f"https://github.com/{package_name}.git"
        print(f"Will clone {repo_url}")
        subprocess.run(['git', 'clone', repo_url, clone_dir])

    elif 'gitlab' in url_obj.netloc:
        repo_url = f"{url_obj.scheme}://{url_obj.netloc}/{package_name}.git"
        print(f"Will clone {repo_url}")
        subprocess.run(['git', 'clone', repo_url, clone_dir])

    ###### Gitweb hosts ######
    elif package_name.startswith('gitweb/'):
        # Gitweb hosts don't have standard paths
        package_name = package_name.split('gitweb/')[1]
        repo_url = check_repo_paths(package_name, url_obj)
        if repo_url is not None:
            print(f"Will clone {repo_url}")
            subprocess.run(['git', 'clone', repo_url, clone_dir])
        else:
            print(f"Unable to find repo for {url}")
            return None

    ###### cgit hosts ######
    elif 'cgit' in url_obj.netloc:
        # cgit hosts don't have standard paths
        repo_url = check_repo_paths(package_name, url_obj)
        if repo_url is not None:
            print(f"Will clone {repo_url}")
            subprocess.run(['git', 'clone', repo_url, clone_dir])
        else:
            print(f"Unable to find repo for {url}")
            return None

    ####### Special case git.kernel.org
    elif 'git.kernel.org' in url_obj.netloc:
        repo_url = f"https://{url_obj.netloc}/{url_obj.path.split('.git')[0]}"
        subprocess.run(['git', 'clone', repo_url, clone_dir])
        return clone_dir

    ####### Special case for pull requests from githubusercontent
    elif 'githubusercontent' in url_obj.netloc:
        repo_url = f"https://github.com/{get_package_name(url)}"
        subprocess.run(['git', 'clone', repo_url, clone_dir])
        return clone_dir

    elif 'git' in url_obj.netloc:
        # cgit hosts don't have standard paths
        repo_url = check_repo_paths(package_name, url_obj)
        if repo_url is not None:
            print(f"Will clone {repo_url}")
            subprocess.run(['git', 'clone', repo_url, clone_dir])
        else:
            print(f"Unable to find repo for {url}")
            return None

    return clone_dir

def get_commit_url_from_release(url):
    tag = url.split('/')[-1]
    package_name = get_package_name(url)

    api_res = requests.get(f"https://api.github.com/repos/{package_name}/git/ref/tags/{tag}")
    if api_res.status_code != 200:
        return None

    res_json = api_res.json()
    if res_json['object']['type'] == 'commit':
        return f"https://www.github.com/{package_name}/commit/{res_json['object']['sha']}"

    api_res = requests.get(res_json['object']['url'])
    if api_res.status_code != 200:
        return None

    res_json = api_res.json()
    if res_json['object']['type'] == 'commit':
        return f"https://www.github.com/{package_name}/commit/{res_json['object']['sha']}"

    return None

def get_commit_urls_from_bugzilla(url):
    url_obj = urlparse(url)
    params = url_obj.query.split('&')
    bug_id = None
    for param in params:
        if param.startswith('id='):
            bug_id = param.split('id=')[1]
            break
    if bug_id is None:
        return []

    try:
        api_res = requests.get(get_redirected_url(f"https://{url_obj.netloc}/rest/bug/{bug_id}/comment"))
    except Exception as e:
        print(f"Exception while fetching url https://{url_obj.netloc}/rest/bug/{bug_id}/comment")
        print(str(traceback.format_exc()))
        return []
    if api_res.status_code != 200:
        return []

    url_list = []
    res_json = api_res.json()
    print(res_json['bugs'].keys())
    for bug_id in res_json['bugs']:
        for comment in res_json['bugs'][bug_id]['comments']:
            for git_source in git_list:
                matches = re.findall(rf'(\S+{git_source}\S+)', comment['text'])
                for match in matches:
                    if urlparse(match).scheme and not any(exclude in match for exclude in git_exclude_list):
                        url_list.append(match)

    return url_list

def sanitize_url(url):
    # Some urls might be URL-encoded, so decode them back to string
    url = unquote(url)

    # Some urls might have the '#' character. These might be links to specific point on landing pages.
    url = url.split('#')[0]

    # Some urls might have the ',' character
    url = url.split(',')[0]

    return url

def get_commit_urls(cve_data):
    commit_urls = defaultdict(list)
    for cve_id in cve_data:
        commit_urls[cve_id] = []
        # deb_sec_refs = get_urls_from_debsec(cve_id)
        if "references" not in cve_data[cve_id]: # and deb_sec_refs == []:
            # Skip this CVE if no references are present
            print(f"No references found for {cve_id}")
            continue

        # Iterate through each reference of the CVE
        refs = list(set([ref['url'] for ref in cve_data[cve_id]['references']]))
        for url in refs:
            # Check if the URL is a git repository
            if any(git in url for git in git_list):
                if not any(exclude in url for exclude in git_exclude_list):
                    # In many cases the first git URL is invalid, and there might be more than one URLs
                    # Keep adding all git URLs, discard bad ones later
                    commit_urls[cve_id].append(url)
            elif 'bugzilla' in url:
                # If the URL is from bugzilla, then we try to find a git URL in the comments
                commits_from_bugzilla = get_commit_urls_from_bugzilla(url)
                commit_urls[cve_id].extend(commits_from_bugzilla)
                for u in commits_from_bugzilla:
                    cve_data[cve_id]['references'].append({
                        "url": u,
                        "name": u,
                        "refsource": url, # The bugzilla URL,
                        "tags": [
                            "Bugzilla Forums"
                        ]
                    })
            else:
                print(f"No git pattern {url}")

        for url_dict in cve_data[cve_id]['references']:
            url = url_dict["url"]
            if url in commit_urls[cve_id]:
                diff_url = get_diff_url(get_redirected_url(sanitize_url(url)))
                if diff_url is None:
                    print(f"{cve_id}: Invalid Diff URL {url}")
                    # Skip processing any invalid URLs
                    continue
                if "tags" not in url_dict:
                    url_dict["tags"] = []
                url_dict["tags"].append("Patch URL")
                url_dict.update({"diff_url": diff_url})

        if commit_urls[cve_id] == []:
            print(f"{cve_id}: No Git URLs found")
    return commit_urls

def get_curl_commit_urls(cve_data):
    commit_urls = defaultdict(list)
    for cve_id in cve_data:
        commit_urls[cve_id] = []
        curl_json_url = f"https://curl.se/docs/{cve_id}.json"
        curl_res = requests.get(get_redirected_url(curl_json_url))
        if curl_res.status_code != 200:
            return
        curl_json = curl_res.json()

        for affected_version in curl_json['affected']:
            for ranges in affected_version['ranges']:
                if str(ranges['type']).lower() != 'git':
                    continue
                repo_url = ranges['repo']
                if not any(git in repo_url for git in git_list):
                    continue
                if repo_url.endswith('.git'):
                    repo_url = repo_url[:-4]

                for events in ranges['events']:
                    if 'fixed' in events:
                        commit_urls[cve_id].append(repo_url + "/commit/" + events['fixed'])

        if commit_urls[cve_id] == []:
            print(f"{cve_id}: No Git URLs found")

        for url in commit_urls[cve_id]:
            diff_url = get_diff_url(get_redirected_url(sanitize_url(url)))
            if diff_url is None:
                print(f"Invaid URL {url}")
                # Skip processing any invalid URLs
                continue
            cve_data[cve_id]['references'].append({
                "url": url,
                "name": url,
                "refsource": curl_json_url,
                "diff_url": diff_url,
                "tags": ["Commit URL"]
            })
    return commit_urls
