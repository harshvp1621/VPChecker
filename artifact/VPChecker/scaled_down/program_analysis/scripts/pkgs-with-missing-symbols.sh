#!/bin/bash

#set -x

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
CHECK_DEBUG=${BASE_DIR}/check-dbg.sh

main()
{
    if [ $# -lt 1 ]; then
	echo "Usage $0 [--verbose] <binary>"
	exit 1
    fi

    verbose=0

    POSITIONAL=()
    while [[ $# -gt 0 ]]; do
	key=$1
	case $key in
	    --verbose)
		verbose=1
		shift
		;;
	    *)
		POSITIONAL+=("$1")
		shift
	esac
    done
    set -- "${POSITIONAL[@]}"

    BIN=$(readlink $1)

    DBG=$(${CHECK_DEBUG} --quiet $1)
    rv=$?

    # if [ $verbose -ne 0 ]; then
    # 	echo "${DBG}"
    # fi

    if [ $rv -ne 0 ]; then
	has_missing=0
	found_packages=0

	to_install=""
	missing_files=""

	for lib in $DBG; do
	    # Try to look up the path
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
		if [ $verbose -ne 0 ]; then
		    echo $res
		fi
		found_packages=1
		to_install="${to_install}\n$(echo ${res} | cut -d: -f 1)"
	    else
		if [ $verbose -ne 0 ]; then
		    echo "MISSING:  ${lib}"
		fi

		has_missing=1
		missing_files="${missing_files}\n${lib}"
	    fi
	done

	if [ $found_packages -ne 0 ]; then
	    # echo -e "Packages requiring installation of debug packages:\n${to_install}\n"
	    echo -e "${to_install}"
	    # cat <<EOF
#Depending on your distribution, debug packages usually take the form
#pkgname-dbgsym or pkgname-dbg.  Exceptions may exist.  Consult your
#package manager (eg. apt-cache search <pkgname>) or distribution
#documentation to find the package names.
#EOF
	fi

	if [ $has_missing -ne 0 ]; then
	    echo "" # Do nothing about missing packages for now
	    # echo -ne "\n"
	    # cat <<EOF
#WARNING: Could not automatically find packages for some libraries.
#Unmapped files may be available from multiple locations due to
#symlinks (eg. /usr/lib and /lib) Try running \`dpkg -S\` with one of
#these alternate paths to find the package
#EOF
	    # echo -e "\nFiles that could not be mapped to packages:\n${missing_files}"
	fi

	if [ -z "${to_install}" ]; then
		return 1
	else
		return 0
	fi
    fi
}

main $@

