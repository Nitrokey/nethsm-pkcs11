#!/bin/sh -x


set -e

# create a new test user 
curl -k -i -w '\n' -u admin:Administrator \
  https://localhost:8443/api/v1/users/testuser -X DELETE

curl -k -i --fail-with-body -w '\n' -u admin:Administrator \
  https://localhost:8443/api/v1/users/testuser -X PUT \
  -H "content-type: application/json" -d "{\"realName\": \"Jane User\",  \
  \"role\": \"Operator\", \"passphrase\": \"testPassphrase\"}"

# create a config file for the test user

sed -e 's/"operator"/"testuser"/g' -e 's/opPassphrase/testPassphrase/g' \
  < p11nethsm.conf > _testuser.conf

# change the pin

P11NETHSM_CONFIG_FILE=_testuser.conf pkcs11-tool --module target/debug/libnethsm_pkcs11.so -c -p testPassphrase --new-pin testPassphrase2

# try to use the new pin

curl -k -i --fail-with-body -w '\n' -u testuser:testPassphrase2 \
  https://localhost:8443/api/v1/keys