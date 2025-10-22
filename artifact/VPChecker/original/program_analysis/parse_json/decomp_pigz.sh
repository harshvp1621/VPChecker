#!/bin/bash

# $1 - tar archive
OUT_DIR="${1}.extracted"
mkdir -p $OUT_DIR

(cd $OUT_DIR; pigz -p 8 -dc $1 | tar xf - )
