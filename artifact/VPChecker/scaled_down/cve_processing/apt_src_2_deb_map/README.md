## APT Resolution Scripts

#### get_apt_src_bin_debs.py
This script creates a mapping from source deb packages to the binary deb packages that are compiled from them

`../../data/apt_src_deb_maps_info.json`

#### get_deb_rdepends.py
This script returns a list of all deb packages that depend on a list of deb packages which provided as the input

`../../data/vuln_debs_rdepends.json`

Run these scripts in a Debian Sid Docker container. You can spin-up a container using the Dockerfile
