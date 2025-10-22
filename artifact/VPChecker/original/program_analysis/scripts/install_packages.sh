#!/bin/bash

MOUNTED_DEB_EXE_DIR="/home/SYSFILTER_ANALYSIS/EXE_DEBS"
MOUNTED_LIBS_DIR="/home/SYSFILTER_ANALYSIS/LIBS"

FAILED_TO_INSTALL="${MOUNTED_DEB_EXE_DIR}/FAILED_INSTALL.lst"
FAILED_TO_INSTALL_DEBUG="${MOUNTED_DEB_EXE_DIR}/NO_DEBUG.lst"

SOMETHING_BAD=238
IS_SO_FILE=239

INPUT_FILE="${MOUNTED_DEB_EXE_DIR}/part"

LIB_DIR="${MOUNTED_LIBS_DIR}/libs/"

mkdir -p "${LIB_DIR}"

GET_DEBUG_PACKAGES="/home/pkgs-with-missing-symbols.sh"

DEB_EXE_LIST=""
DEB_SO_LIST=""
# set -x

cleanup () {
	rm -rf ${FAILED_TO_INSTALL_DEBUG} ${FAILED_TO_INSTALL}
}

check_if_executable () {
	# Return 0 only if the file is a dynamic executable

	bin="${1}"

	# Better test to check if dynamic binary
	# Readelf returns 0 exit code even if dynamic section is absent
	objdump -T "${bin}" >/dev/null 2>&1

	is_elf=$?

	if [ $is_elf -ne 0 ]; then
		return $SOMETHING_BAD
	fi

	# echo "Testing ${bin}"
	output=$(readelf -d ${bin} 2>/dev/null)

	if echo $output | grep -q "SONAME"; then
		return $IS_SO_FILE
	fi

	# Some shared objects do not have the SONAME field
	output=$(file ${bin} 2>/dev/null)

	if echo $output | grep -q "shared object"; then
		return $IS_SO_FILE
	fi
	return 0
}

find_and_copy_debug_symbols() {
	#$1 - Elf Binary
	elf="${1}"
	build_id=$(file $(readlink -f $elf) | sed -e 's/.*BuildID\[sha1\]=\([^,]*\).*/\1/')
	if [[ -f /usr/lib/debug/.build-id/${build_id:0:2}/${build_id:2}.debug ]]; then
	    file_dir="${elf%/*}"
	    echo "Copying debug symbols for ${elf} to ${file_dir}"
	    cp /usr/lib/debug/.build-id/${build_id:0:2}/${build_id:2}.debug "${file_dir}"
	else
		echo "Debugging symbols NOT FOUND for $elf"
	fi
}

install_debug_syms() {
        # $1 - ELF binary for which debug symbols are needed
        elf="${1}"

        debug_packages=( $(${GET_DEBUG_PACKAGES} ${elf}) )
        ret_val=$?

        if [ $ret_val -eq 0 ]; then
               for dbg in "${debug_packages[@]}"; do
                        if DEBIAN_FRONTEND=noninteractive apt install -y "${dbg}-dbgsym" > /dev/null 2>&1; then
                                echo "Install Debug ${dbg}-dbgsym"
			elif DEBIAN_FRONTEND=noninteractive apt install -y "${dbg}-dbg" > /dev/null 2>&1; then
				echo "Install Debug ${dbg}-dbg"
			else
                                echo "${dbg}" >> $FAILED_TO_INSTALL_DEBUG
                        fi
                done
        fi
}

install_package () {
	# $1 - Package

	package="${1}"
	if DEBIAN_FRONTEND=noninteractive apt install ${package} -y > /dev/null 2>&1 ; then
		echo "Installed ${package}"
	else
		echo "${package}" >> $FAILED_TO_INSTALL
		# If failed to install main package, just return
		return $SOMETHING_BAD
	fi

	CURRENT_PACK_VERSION=$(apt-cache policy "$package" | grep 'Candidate:' | awk '{print $2}')
	if [ -z "$CURRENT_PACK_VERSION" ]; then
		CURRENT_PACK_VERSION="__ver_not_found"
	fi

	DEB_FILES=( $(dpkg-query -L ${package} ) )
        ret_val=$?

        if [ $ret_val -ne 0 ]; then
                return $SOMETHING_BAD
        fi

        for file in "${DEB_FILES[@]}"; do
		check_if_executable $file
		is_exe=$?
                if [ $is_exe -eq 0 ]; then
                        DEB_EXE_LIST="${DEB_EXE_LIST} ${file}"
                        install_debug_syms $file
		elif [ $is_exe -eq $IS_SO_FILE ]; then
			DEB_SO_LIST="${DEB_SO_LIST} ${file}"
			install_debug_syms $file
                fi
        done

	# Install dbgsym packages of the dependencies
	#DEPS=( $(apt-cache depends ${package} | awk '{split($0,a,": "); print a[2]}') )
	#echo "${DEPS}"
	#for dep in "${DEP[@]}"; do
	#	if DEBIAN_FRONTEND=noninteractive apt install "${dep}-dbgsym" > /dev/null 2>&1; then
	#		echo "Installed ${package}"
	#	else
	#		echo "${package}-dbgsym" >> $FAILED_TO_INSTALL_DEBUG
	#	fi
	#done
}

run_sysfilter_so_file () {
	# $1 - Full shared object file path
	# $2 - Deb package name
	# $3 - out directory

	so_file=$1
	deb_package=$2
	so_file_name=$(basename ${so_file})
	out_dir=$3

	readelf --dyn-syms --wide $so_file | tail -n +5 | grep -v "UND" | awk '{print "\x22"$8"\x22,"}' > ${out_dir}/${so_file_name}.exported.json
	sed -i '$ s/.$//' ${out_dir}/${so_file_name}.exported.json
	sed -i '1 i\[' ${out_dir}/${so_file_name}.exported.json
	sed -i '$a \]' ${out_dir}/${so_file_name}.exported.json
	mkdir -p ${out_dir}/${so_file_name}.FCG_SYM

	# Run sysfilter and store the output in the FCG folder for the shared object
	sysfilter_extract --disable-nss --fcg-only --dump-fcg --entry-symbol-file "${out_dir}/${so_file_name}.exported.json" -o "${out_dir}/${so_file_name}.FCG_SYM/" "$so_file" > /dev/null 2>&1

	# Delete all the empty files
	find "${out_dir}/${so_file_name}.FCG_SYM/" -type f -empty -delete

	# Compress the JSON files
	# tar -c -I 'xz -9 -T0' -f "${out_dir}/${so_file_name}.tar.xz" "${out_dir}/${so_file_name}.FCG_SYM"
	tar -cf - "${out_dir}/${so_file_name}.FCG_SYM" | pigz -9 -p 8 > "${out_dir}/${so_file_name}.tar.gz" 
	rm -rf "${out_dir}/${so_file_name}.FCG_SYM"
}

copy_ldd_libs () {

	# $1 = binary
	BIN=$1
	to_install=""
	missing_files=""
	for lib in $(ldd $BIN | awk -F"=>" '{print $2}' | awk '{print $1}'); do
		# echo "Checking ${lib}..."
		lib_name=$(basename $lib)
		res=$(dpkg -S ${lib} 2> /dev/null)
		resrv=$?

            	# If we didn't get a hit, and the path begins with /usr, strip /usr and try again
            	if [ $resrv -ne 0 ]; then
                	res=$(echo ${lib} | sed 's/^\/usr//g' | xargs dpkg -S 2> /dev/null)
                	resrv=$?
            	fi

            	# If we still didn't get a hit, just try adding /usr and try again
            	if [ $resrv -ne 0 ]; then
                	res=$(echo "/usr${lib}" | xargs dpkg -S 2> /dev/null)
                	resrv=$?
            	fi

            	if [ $resrv -eq 0 ]; then

                	lib_deb="$(echo ${res} | cut -d: -f 1)"
			lib_ver=$(apt-cache policy "$lib_deb" | grep 'Candidate:' | awk '{print $2}')
        		if [ -z "$lib_ver" ]; then
                		lib_ver="__ver_not_found"
        		fi
			lib_deb_ver="${lib_deb}_${lib_ver}"

			if [ -f "${LIB_DIR}/${lib_deb_ver}/${lib_name}" ]; then
				# This lib was already processesd, continue
				continue
			fi
			mkdir -p "${LIB_DIR}/${lib_deb_ver}"
			cp $lib "${LIB_DIR}/${lib_deb_ver}/"
			find_and_copy_debug_symbols "${LIB_DIR}/${lib_deb_ver}/${lib_name}"
			run_sysfilter_so_file $lib $lib_deb_ver "${LIB_DIR}/${lib_deb_ver}"
            	else
			mkdir -p "${LIB_DIR}/unresolved"
			cp $lib "${LIB_DIR}/unresolved/"
			# Do not run sysfilter for unresolved libs, we will run separately for them at the end of data collection
            	fi
	done
}

run_sysfilter () {
	# $1 - Package
	package="${1}"
	package_name_ver="${package}_${CURRENT_PACK_VERSION}"
	#files=( $(dpkg-query -L ${package}) )
	#ret_val=$?
	#if [ $ret_val -ne 0 ]; then
	#	return $SOMETHING_BAD
	#fi
	DEB_EXE_LIST=( ${DEB_EXE_LIST} )
	for file in "${DEB_EXE_LIST[@]}"; do
		if [[ -d $file ]]; then
			continue
		fi
		#check_if_executable $file
		#ret_val=$?
		#if [ $ret_val -eq 0 ]; then
		echo "Checking $file"
		base_name=$(basename ${file})
		copy_ldd_libs $file
		mkdir -p "${MOUNTED_DEB_EXE_DIR}/${package_name_ver}/"
		echo "Created Dir ${MOUNTED_DEB_EXE_DIR}/${package_name_ver}"
		cp $file "${MOUNTED_DEB_EXE_DIR}/${package_name_ver}/"
		find_and_copy_debug_symbols "${MOUNTED_DEB_EXE_DIR}/${package_name_ver}/${base_name}"
		echo "Running sysfilter  on ${base_name} from package ${package_name_ver}"
		# sysfilter writes directly to tty
		sysfilter_extract --fcg-only --disable-nss --dump-fcg $file &> "${MOUNTED_DEB_EXE_DIR}/${package_name_ver}/${base_name}.fcg.json"
		ret_val=$?
		if [ $ret_val -ne 0 ]; then
		       mv "${MOUNTED_DEB_EXE_DIR}/${package_name_ver}/${base_name}.fcg.json" "${MOUNTED_DEB_EXE_DIR}/${package_name_ver}/${base_name}.fcg.error"
	        fi
	done

	DEB_SOFILE_LIST=( ${DEB_SO_LIST} )
	for file in "${DEB_SOFILE_LIST[@]}"; do
		if [[ -d $file ]]; then
			continue
		fi
		echo "Checking shared object $file"
		base_name=$(basename ${file})
		if [ -f "${LIB_DIR}/${package_name_ver}/${base_name}" ]; then
			# This lib was already processesd, continue
                        continue
                fi
		echo "Running Sysfilter on ${base_name}"
		copy_ldd_libs $file
		mkdir -p "${LIB_DIR}/${package_name_ver}"
		cp $file "${LIB_DIR}/${package_name_ver}"
		run_sysfilter_so_file $file $package "${LIB_DIR}/${package_name_ver}"
	done
}

purge_package () {
	# $1 - package
	# This might happen when we are accidentally trying to remove a critical deb package
	DEBIAN_FRONTEND=noninteractive apt purge -y ${1} || echo "Failed to remove ${1}"
	DEBIAN_FRONTEND=noninteractive apt autoremove -y || echo "Failed to autoremove"
}

while read -r deb_name
do
	DEB_EXE_LIST=""
	DEB_SO_LIST=""
	install_package ${deb_name}
	installed=$?
	if [ $installed -eq 0 ]; then
		if [ -z "${DEB_EXE_LIST}" ]; then
		      # Some debs might not have any executable binary
		      continue
		fi
		run_sysfilter $deb_name
	fi
	purge_package ${deb_name}
done < ${INPUT_FILE}*
