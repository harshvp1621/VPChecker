#!/bin/bash

pr_info () {
	echo "I: ${1}"
}

apply_sysfilter_patches () {
	pr_info "Applying sysfilter patches"
	cd sysfilter
	git config user.email "anon@anon.com"
	git config user.name "Anon"
	git am -3 ../patches/*.patch
	cd -
}

# Clone Sysfilter First
git clone --recursive git@gitlab.com:egalito/sysfilter

(
	cd sysfilter;
	git reset --hard 1469319ba6ea7cab87638c1f879541e78d72d470
)

apply_sysfilter_patches

