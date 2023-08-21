#!/bin/sh

set -e

curl -k -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/edkey


./container/nginx/generate.sh

export P11NETHSM_CONFIG_FILE=~/git/nethsm-pkcs11/p11nethsm.conf
export OPENSSL_CONF=$PWD/_openssl.cnf