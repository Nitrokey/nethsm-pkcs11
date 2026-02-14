#!/bin/bash -x

set -e

if [[ $NETHSM_VERSION == v1.* ]] || [[ $NETHSM_VERSION == v2.* ]]
then
  exit
fi

# NetHSM        PKCS11            comment
#
# 0---FF        FF                encoded ID (trivial case)
# 0---2D6B6579  2D6B6579          encoded ID (more complex case)
# 0---F         302D2D2D46        non-encoded ID (odd number of characters)
# 0---FK        302D2D2D464B      non-encoded ID (bad hex character)
# 0---6B        302D2D2D3642      non-encoded ID (encoding not necessary)
# p11-test      7031312D74657374  non-encoded ID (valid key ID)

nethsm_key_ids="0---FF 0---2D6B6579 0---F 0---FK 0---6B p11-test"
pkcs11_key_ids="ff 2D6B6579 302D2D2D46 302D2D2D464B 302D2D2D3642 7031312D74657374"

# Part 1: Create key via API and check PKCS11 ID

for key_id in $nethsm_key_ids
do
  curl -k --fail-with-body -i -w '\n' -u admin:Administrator -X POST \
    https://localhost:8443/api/v1/keys/generate \
    -H "content-type: application/json" \
    -d '{ "mechanisms": [
  "ECDSA_Signature"
  ],  "type": "EC_P256", "id": "'$key_id'" }'
done

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so -O --type pubkey
for key_id in $pkcs11_key_ids
do
  echo "reading $key_id via pkcs11"
  pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so --id $key_id --read-object --type pubkey --output-file /tmp/key.der
  echo
done

for key_id in $nethsm_key_ids
do
  curl -k -u admin:Administrator -v -X DELETE \
    https://localhost:8443/api/v1/keys/$key_id
done

# Part 2: Create key via PKCS11 and check NetHSM ID

for key_id in $pkcs11_key_ids
do
  pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so -k --key-type EC:prime256v1 \
      --login --login-type so --so-pin Administrator --id $key_id
done

for key_id in $nethsm_key_ids
do
  curl -k --fail-with-body -u admin:Administrator -v -X DELETE \
    https://localhost:8443/api/v1/keys/$key_id
done

# Part 3: Create key via PKCS11, rename via PKCS11 and check NetHSM ID

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so -k --key-type EC:prime256v1 \
    --login --login-type so --so-pin Administrator --id ff
pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v  \
  --set-id 2D6B6579 --type privkey --id ff --login --login-type so --so-pin Administrator
curl -k --fail-with-body -u admin:Administrator -v -X DELETE \
  https://localhost:8443/api/v1/keys/0---2D6B6579
