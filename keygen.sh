#!/bin/bash
#
# Copyright (c) 2020 kapsules.io.  All rights reserved.
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

#
# Generates a Elliptict Cryptography keypair using openssl

set -e

function usage {
  echo "Usage: $(basename $0) KEY [DIR]

    KEY     the name of the key pair to generate, required
    DIR     optionally, a directory where to store the keys.

This script generates a private (KEY.pem) and public (KEY-pub.pem) pair using openssl; the keys are generated using Elliptic Cryptography.
See: https://github.com/auth0/java-jwt/issues/270
"
}

KEY=${1:-}
DIR=${2:-}

if [[ -z ${KEY} ]]; then
  usage
  exit 1
fi

PRIV=${KEY}.pem
PUB=${KEY}-pub.pem

# Generate the EC Param
openssl ecparam -name prime256v1 -genkey -noout -out ${KEY}-param.pem

# Generate the Private Key
openssl pkcs8 -topk8 -inform pem -in ${KEY}-param.pem -outform pem \
    -nocrypt -out ${PRIV}

# From the Private key, extract the Public Key
openssl ec -in ${PRIV} -pubout -out ${PUB}

rm ${KEY}-param.pem
echo "[SUCCESS] Key Pair generated: ${PRIV} / ${PUB}"

if [[ -n ${DIR} && -d ${DIR} ]]; then
  mv ${PRIV} ${PUB} ${DIR}
  echo "[SUCCESS] Keys stored in ${DIR}"
  ls ${DIR}/${KEY}*
fi
