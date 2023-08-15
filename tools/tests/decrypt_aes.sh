#!/bin/sh -x

set -e 


KEYID=aeskeytemp

HEXID=$(echo -n ${KEYID} | xxd -ps)


# We need to have access to the private key, so we need to generate it locally and then upload it to the HSM

openssl rand -out _aes.key 32 

B64=$(base64 _aes.key)

curl -k -i -w '\n' -u admin:Administrator -X DELETE \
  https://localhost:8443/api/v1/keys/$KEYID \


curl -k -i --fail-with-body -w '\n' -u admin:Administrator -X PUT \
  https://localhost:8443/api/v1/keys/$KEYID \
  -H "content-type: application/json" \
  -d '{
    "mechanisms": [ 
      "AES_Encryption_CBC",
      "AES_Decryption_CBC"
      ],
    "type": "Generic",
    "key": {
      "data": "'$B64'"
    }
}'

rm -rf _data.crypt _input _data.decrypt

IV=$(openssl rand -hex 16)

echo -n "NetHSM rulez!  NetHSM rulez!    "  > _input


openssl aes-256-cbc -nopad -in _input -out _data.crypt -K $(cat _aes.key | xxd -c 256 -p) -iv $IV

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v --decrypt \
  --mechanism AES-CBC --input-file _data.crypt --id $HEXID \
  --iv $IV --output-file _data.decrypt

diff _input _data.decrypt
  