#!/usr/bin/env bash
#
# Copyright (c) 2022 AlertAvert.com.  All rights reserved.
# Author: Marco Massenzio (marco@alertavert.com)
#
# Extracts version from build.gradle
#
set -eu
workdir=$(dirname $0)

grep -E '^[[:blank:]]*version' ${workdir}/jwt-opa/build.gradle |\
    sed -E 's/^[[:blank:]]*version[[:blank:]]*=?[[:blank:]]*//' |\
    sed "s/'//g" | sed 's/[[:blank:]]*$//'
