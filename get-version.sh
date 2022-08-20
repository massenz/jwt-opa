#!/usr/bin/env bash
#
# Copyright (c) 2022 AlertAvert.com.  All rights reserved.
# Author: Marco Massenzio (marco@alertavert.com)
#
# Usage: get-version [build]
# Extracts version from build.gradle
#
# build is the path to the build.gradle file, defaults to ./build.gradle

set -eu

build=${1:-build.gradle}

# Note the use of -E to enable "extended" RegExps syntax (* and ?).
grep -E '^[[:blank:]]*version' ${build} |\
    sed -E 's/^[[:blank:]]*version[[:blank:]]*=?[[:blank:]]*//' |\
    sed "s/'//g" | sed 's/[[:blank:]]*$//'
