#!/bin/bash

pr_info () {
	echo "I: ${1}"
}

cleanup () {
	pr_info "Performing cleanup"
	rm -rf docker_vols/vol*
}

setup_volumes () {
	pr_info "Setting-up volumes"
	# Replace 'input_file.txt' with the name of your input file
	# input_file="FINAL_ANALYSIS_DEB_LIST.txt"
	input_file="TOP_10_POPULAR_DEBS_LIST.txt"

	# Define the number of parts
	num_parts=10

	# Calculate the number of lines per part
	total_lines=$(wc -l < "$input_file")
	lines_per_part=$((total_lines / num_parts))

	# Use split to split the file into parts
	split -l "$lines_per_part" "$input_file" part

	# Rename the output files
	for f in part*; do
		mkdir -p "docker_vols/vol${f:(-2)}"
		mv $f "docker_vols/vol${f:(-2)}"
	done
}

load_docker_image () {
	pr_info "Loading sysfilter:patched Docker image"
	docker load -i ./sysfilter_image/sysfilter_patched.tar
	pr_info "Done"
}

cleanup

setup_volumes
load_docker_image
