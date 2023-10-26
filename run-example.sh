#!/usr/bin/env bash
#
# Copyright (c) 2021 AlertAvert.com.  All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
# http://www.apache.org/licenses/LICENSE-2.0
#
# Author: Marco Massenzio (marco@alertavert.com)
set -eu

WORKDIR=$(dirname $0)
OPA_PORT=8181
OPA_SERVER=http://localhost:${OPA_PORT}
POLICY_API=${OPA_SERVER}/v1/policies/userauth

docker compose --project-name jwt-opa up -d
if [[ $(curl -s ${POLICY_API} | jq .result.id) != "userauth" ]]; then
    echo "Uploading userauth Policy"
    curl -T "${WORKDIR}/webapp-example/src/main/rego/jwt_auth.rego" -X PUT ${POLICY_API}
fi

echo "Containers started, starting server..."
export SPRING_PROFILES_ACTIVE="${1:-dev}"
${WORKDIR}/gradlew  :webapp-example:bootRun
