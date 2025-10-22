#!/bin/bash

main()
{
    if [[ $1 == "" ]]; then
	echo "Usage: $0 [--quiet] binary"
	echo "  --quiet:  Print only libraries for which symbols could not be found"
	echo "Return code is 0 if all relevant debug symbols were found."
	return 1
    fi

    quiet=0
    POSITIONAL=()

    while [[ $# -gt 0 ]]; do
	key=$1
	case $key in
	    -q|--quiet)
		quiet=1
		shift
		;;
	    *)
		POSITIONAL+=("$1")
		shift
	esac
    done
    set -- "${POSITIONAL[@]}"
    BIN=$1

    ecode=0

    for f in $BIN $(ldd $BIN | awk -F"=>" '{print $2}' | awk '{print $1}'); do
	build_id=$(file $(readlink -f $f) | sed -e 's/.*BuildID\[sha1\]=\([^,]*\).*/\1/')
	if [[ -f /usr/lib/debug/.build-id/${build_id:0:2}/${build_id:2}.debug ]]; then
	    if [ $quiet -eq 0 ]; then
		echo "Debugging symbols for $f found"
	    fi
	else
	    if [ $quiet -eq 0 ]; then
		echo "Debugging symbols NOT FOUND for $f"
	    else
		echo $f
	    fi
            ecode=1
	fi
    done

    return $ecode
}

main $@
