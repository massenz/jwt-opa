#!/usr/bin/env bash
#
# Copyright (c) 2022 AlertAvert.com.  All rights reserved.
# Author: Marco Massenzio (marco@alertavert.com)

set -eu

declare -r tag=$($(dirname $0)/get-version.sh)
echo "Creating new tag ${tag}"

if git tag | grep ${tag}
then
    echo -n "Tag ${tag} exists: "
    if [[ ${1:-} == "-f" ]]
    then
        echo "replacing it"
        git tag -d ${tag}
        git push origin :${tag}
    else
        echo "-f not specified, stopping"
        exit 1
    fi
fi

git tag ${tag}
git push --tags
