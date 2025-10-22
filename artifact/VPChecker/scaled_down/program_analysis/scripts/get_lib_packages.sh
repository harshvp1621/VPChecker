#!/bin/bash

main() {

	# $1 = binary
	BIN=$1
	to_install=""
	missing_files=""
	for lib in $(ldd $BIN | awk -F"=>" '{print $2}' | awk '{print $1}'); do
		# echo "Checking ${lib}..."
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
                	to_install="${to_install}\n$(echo ${res} | cut -d: -f 1)"
            	else
                	missing_files="${missing_files}\n${lib}"
            	fi
	done

	echo -e $to_install
	echo $missing_files
}

main $@
