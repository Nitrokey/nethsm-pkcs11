#!/bin/sh -x

set -e 

rm -rf _aes.key _crypt.json _data.dec _data.crypt _iv.bin data.txt _decrypted.txt

openssl rand -out _aes.key 32

OUTPUT=$(pkcs11-tool --module target/debug/libnethsm_pkcs11.so -y secrkey --write-object _aes.key --login --login-type so --so-pin Administrator)

id=$(echo "$OUTPUT" | awk '/label:/{print $2}')

# encrypt with openssl aes-256-cbc

IV=$(openssl rand -hex 16)

echo "NetHSM rulez!  " > _data.txt

openssl aes-256-cbc -in _data.txt -out _data.crypt -K $(cat _aes.key | xxd -c 256 -p) -iv $IV

# decrypt with api call 
echo -n $IV | base64
curl -k --fail-with-body -u operator:opPassphrase -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"mode":"AES_CBC","iv":"'$(echo -n $IV | xxd -r -p | base64)'","encrypted":"'$(cat _data.crypt | base64)'"}' \
  https://localhost:8443/api/v1/keys/$id/decrypt > _data.dec

# verify
decrypted=$(jq -r '.decrypted' _data.dec | base64 -d| tr -d '' > _decrypted.txt)

diff _data.txt _decrypted.txt