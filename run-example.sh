#!/usr/bin/env bash
#
# Running the service with the containers it relies on.

set -eux

WORKDIR=$(dirname $0)

if [[ -z $(docker ps --filter name=mongo | grep -w mongo) ]]; then
    echo "Starting MongoDB container"
    docker run --rm -d -p 27017:27017 --name mongo mongo:4.0
fi
if [[ -z $(docker ps --filter name=opa | grep -w opa) ]]; then
    echo "Starting Open Policy Agent (OPA) container"
    docker run --rm -d -p 8181:8181 --name opa openpolicyagent/opa:0.25.2 run --server
fi

export SPRING_PROFILES_ACTIVE="debug"

echo "Containers started, starting server..."
${WORKDIR}/gradlew  :webapp-example:bootRun
