#!/usr/bin/env bash
#
# Copyright (c) 2021 AlertAvert.com.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Marco Massenzio (marco@alertavert.com)
# Running the service with the containers it relies on.

set -eux

WORKDIR=$(dirname $0)

OPA_PORT=8181
OPA_SERVER=http://localhost:${OPA_PORT}
POLICY_API=${OPA_SERVER}/v1/policies/userauth

docker-compose up -d
if [[ $(curl -s ${POLICY_API} | jq .result.id) != "userauth" ]]; then
    echo "Uploading userauth Policy"
    curl -T "${WORKDIR}/webapp-example/src/main/rego/jwt_auth.rego" -X PUT ${POLICY_API}
fi

export SPRING_PROFILES_ACTIVE="debug"

echo "Containers started, starting server..."
${WORKDIR}/gradlew  :webapp-example:bootRun
