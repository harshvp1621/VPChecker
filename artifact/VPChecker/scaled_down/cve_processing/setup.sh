#!/bin/bash

# Install Git and Universal Ctags
sudo apt install -y git universal-ctags

# First clone the CVE V5 repository
git clone https://github.com/CVEProject/cvelistV5.git

(  cd cvelistV5; git checkout f9c96b8deb8055831ef9898c64b8a4891acf0cfb )

# Merge git references from CVE V5 records and Debian Security Tracker
python3 merge_deb_sec_cves.py 
