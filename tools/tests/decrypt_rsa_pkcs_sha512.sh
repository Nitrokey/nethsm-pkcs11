#!/bin/sh -x

set -e

KEYID=rsakey

HEXID=$(echo -n ${KEYID} | xxd -ps)

rm -rf _data.crypt _public.pem _input _data.decrypt

curl -k -s --fail-with-body -u operator:opPassphrase -X GET \
  https://localhost:8443/api/v1/keys/$KEYID/public.pem -o _public.pem

echo 'NetHSM rulez!' > _input 

openssl pkeyutl -encrypt -pubin -inkey _public.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha512 \
  -pkeyopt rsa_mgf1_md:sha512 -out _data.crypt -in _input

pkcs11-tool --module ./target/debug/libnethsm_pkcs11.so  -v --decrypt \
  --mechanism RSA-PKCS-OAEP --input-file _data.crypt --id $HEXID \
  --hash-algorithm SHA512 --output-file _data.decrypt

# the input should be the same as the output
diff _input _data.decrypt