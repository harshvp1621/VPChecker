#!/bin/bash
# $1 - Deb File Path
# $2 - Extract parent path

DEB_FILE="$1"
TARGET_PARENT_PATH="$2"

DEB_D_PATH="${TARGET_PARENT_PATH}/${DEB_FILE}.d"

mkdir "${DEB_D_PATH}"

ar x "${TARGET_PARENT_PATH}/${DEB_FILE}" --output "${DEB_D_PATH}"


cd "${DEB_D_PATH}";
mkdir -p deb_data;
tar --use-compress-program=unzstd -xvf data.tar.zst -C ./deb_data
chmod +w -R ./deb_data
rm -rf *.zst;

files=($(find ./deb_data -type f))

for file in "${files[@]}"; do
	objdump -T ${file} || rm -f $file
done

find ./deb_data/ -type d -empty -delete

cd -
