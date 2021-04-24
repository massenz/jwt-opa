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
#

#
# Created by M. Massenzio, 2021-04-21

set -e

USER=alice
USER_PASS=zekre7

# See the db.admin.password property in application.yaml
ADMIN_PASS=${1:-8535b9c4-a}

http :8080/health | grep "UP"

ADMIN_TOKEN=$(http :8080/login --auth admin:${ADMIN_PASS} | jq .api_token | sed 's/\"//g')
if [[ -z ${ADMIN_TOKEN} ]]; then
    echo "ERROR Could not authenticate admin user"
    exit 1
fi
echo "SUCCESS Admin user logged in"

# Usernames must be unique, so we need to remove it first, if it exists.
USER_ID=$(http :8080/users/${USER} "Authorization:Bearer ${ADMIN_TOKEN}" | jq .user_id)
if [[ -n ${USER_ID} ]]; then
    http DELETE :8080/users/${USER} "Authorization:Bearer ${ADMIN_TOKEN}" > /dev/null
fi

USER_ID=$(http POST :8080/users username=${USER} password=${USER_PASS} \
    roles:='["EDITOR", "DATA_ANALYST", "USER"]' \
    "Authorization:Bearer ${ADMIN_TOKEN}" | jq .user_id)
if [[ -z ${USER_ID} ]]; then
    echo "ERROR Cannot create user"
    exit 1
fi
echo "SUCCESS Created user ${USER} [${USER_ID}]"

USER_TOKEN=$(http :8080/login --auth ${USER}:${USER_PASS} | jq .api_token | sed 's/\"//g')
if [[ -z ${USER_TOKEN} ]]; then
    echo "ERROR Could not authenticate user ${USER}"
    exit 1
fi

ROLES=$(http :8080/users/${USER} "Authorization:Bearer ${USER_TOKEN}" \
    | jq .roles)
if [[ -z ${ROLES} ]]; then
    echo "ERROR Could not retrieve user ${USER} data, using API Token ${USER_TOKEN}"
    exit 1
fi
echo "SUCCESS User ${USER} with ROLES=${ROLES}"

echo "SUCCESS All tests passed"
