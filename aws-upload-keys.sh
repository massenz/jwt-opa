#!/bin/bash
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
# Generates a Elliptict Cryptography keypair using openssl

set -eu

function usage {
  echo "Usage: $(basename $0) KEY SECRET

    KEY     the path to the key pair to upload, WITHOUT extension
    SECRET  the name of the secret to create in AWS Secrets Manager

This script uploads a key pair named 'KEY.pem' and 'KEY.pub' to AWS Secrets Manager,
using the \$AWS_PROFILE env var to obtain the credentials and the region to upload to.

Use \$AWS_ENDPOINT to specify a custom endpoint for the Secrets Manager service, if not using
the default AWS endpoint (eg, when testing against a localstack container, you can use
http://localhost:4566).

The pair can be generated using the keygen.sh script.
Requires the aws binary CLI (https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
"
}

KEY=${1:-}
SECRET=${2:-}
ENDPOINT_URL=""

if [[ -z ${KEY} || -z ${SECRET} || ${1:-} == "-h" ]]; then
  usage
  exit 1
fi

if [[ -z $(which aws) ]]
then
  usage
  echo "ERROR: This script requires the aws CLI to upload the keys to Secrets Manager"
  exit 1
fi

if [[ -n ${AWS_ENDPOINT:-} ]]; then
  ENDPOINT_URL="--endpoint-url ${AWS_ENDPOINT}"
fi

PRIV=${KEY}.pem
PUB=${KEY}.pub
if [[ ! -f ${PRIV} || ! -f ${PUB} ]]; then
  usage
  echo "ERROR: Cannot find ${PRIV} and/or ${PUB} keys"
  exit 1
fi

out=$(mktemp /tmp/secret-XXXXXXXX.tmp)
cat <<EOF >$out
{
  "priv": "$(while read -r line; do if [[ ! ${line} =~ ^----- ]]; \
      then echo -n ${line}; fi; done < ${PRIV})",
  "pub": "$(while read -r line; do [[ ${line} =~ ^----- ]] || echo -n ${line}; done < ${PUB})",
  "algorithm": "EC"
}
EOF


arn=$(aws ${ENDPOINT_URL} secretsmanager create-secret --name ${SECRET} \
  --description "Keypair ${KEY} generated by the $(basename $0) script" \
  --secret-string file://${out} | jq -r '.ARN')

rm $out
echo "[SUCCESS] Key Pair ${KEY} uploaded to AWS: ${arn}"
