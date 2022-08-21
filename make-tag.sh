#!/usr/bin/env bash
#
# Copyright (c) 2022 AlertAvert.com.  All rights reserved.
# Author: Marco Massenzio (marco@alertavert.com)

set -eu

declare -r BASEDIR=$(dirname $0)
declare -r BUILD=${BASEDIR}/jwt-opa/build.gradle
declare -r tag=$(${BASEDIR}/get-version.sh ${BUILD})

if [[ -z ${tag} ]]
then
  echo "[ERROR] Could not extract version information from build.gradler"
  exit 1
fi

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

git tag -am "Rel. ${tag}" ${tag}
git push --tags
