# Creating the CVE dataset

Execute `setup.sh`

## Debian_Sec_Dataset.ipynb
This notebook performs data crunching to determine the following:
- List of deb sources that would compile into atleast one `library` binary deb
  package
- List of CVE reported for such deb sources

This jupyter notebook produces the following files:
- `../../notebooks/data/vuln_apt_sources.txt`

## Collecting vulnerable function names for CVEs

Here we run the script `run_large_scale.py` which produces a json file for each
apt source with CVE reported 2022 onwards. Note that these CVEs were extracted
from the file `../../notebooks/data/deb_sec_tracker_merged_2022.json`.

The `run_large_scale.py` internally calls the script `json_to_func.py` which
creates a JSON for each CVE containing a list of files and the names of
functions that were modified as part of a patch for the CVE. After the script
ends, this is how the directory tree would look like for a deb source:

```
cve_json_feed/openssl/
├── cves
│   ├── CVE-2022-0778.json # CVE record augmented with vuln func information
.   .
.   .
.   .
│   └── CVE-2024-4741.json
├── openssl.cves.json # List of all CVEs and references for Debian's openssl
├── openssl.funcs.json # Mapping of all CVEs and vulnerable functions
└── openssl.out # Runtime/Error Logs
```
The dataset used for the paper is available in the directory `cve_json_feed`.

## Analyzing the data collected
Many CVE do not have a git commit link, so they will not have any vulnerable
functions listed for them. Also we look for changes only in C/C++ patch files
and ignore the rest.

## Determining potentially vulnerable binary deb packages
First we need to find out a list of deb sources for which we were able to get a
CVE to vulnerable function matching. For some deb sources, either there was no
CVE reported after 2022 or the changes were not in C/C++ code files. Refer to
comments in `../../notebooks/Deb_Sec_Dataset.ipynb` for more details.

The final output of this analysis is the following:
- a list of CVEs for which we could find a vulnerable function from a patch
  fixing a C/C++ code file `../../notebooks/data/cve_funcs_git_src_tuples.csv`
- a list of apt sources that have atleast one CVE for which we could find a
  vulnerable function `../../notebooks/data/vuln_apt_sources.txt`
- a list of binary deb packages that depend on the above apt sources
  `../../notebooks/data/FINAL_DEB_LIST_OF_APT_SRCS.txt`
- a list of debs that depend on the binary deb packages of vulnerable apt
  sources `../../notebooks/data/FINAL_ANALYSIS_DEB_LIST.txt`

## Performing a Lookup of Vulnerable functions

This step is performed by the jupyter notebook
`../../notebooks/CVE_Lookup.ipynb`. However, this should only be done after
FCGs of all binaries in your software supply chain have been uploaded into the
ArangoDB Graph Database.

For information on how to collect FCG data and store into Graph Database, look
into the folder `../docker`

## CVE_Lookup.ipynb

The analysis in this notebook can only be performed after all graphs have been
created. Here we take a list of all CVEs for which we found atleast one
vulnerable function using the `Deb_Sec_Dataset.ipynb` notebook, and perform a
lookup of their functions in the graph database. The two files produced by this
analysis are:
- `../../notebooks/data/cve_lookup_details.json` - A detailed mapping of CVEs
  and vulnerable function nodes found in the graph. Note that for a lot of
CVEs, the list of functions will be empty. More information in the Dataset
section of the paper
- `../../notebooks/data/cve_funcs_debs_elfs_found.csv` - A list of tuples for
  each vulnerable function that was found in our database. A sample tuple looks
like:
```
< CVE-2022-32206,
    libcurl4t64_8.8.0-2,
    libcurl.so.4,
    Curl_build_unencoding_stack@libcurl.so.4@libcurl4t64_8.8.0-2,
    FIXED >
```
