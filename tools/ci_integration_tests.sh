#!/bin/sh -x

set -e

echo "Starting tests"

export P11NETHSM_CONFIG_FILE=./p11nethsm.conf

./tools/test_decrypt_sha1.sh
./tools/test_decrypt_sha256.sh
./tools/test_decrypt_sha512.sh
./tools/test_decrypt.sh
./tools/test_encrypt_aes.sh
./tools/test_ec_sign.sh
./tools/test_sign.sh
./tools/test_sign_sha1.sh
./tools/test_sign_sha256.sh
./tools/test_upload_ec_key.sh
./tools/test_upload_ec_key_id.sh
# doesn't work, pkcs11-tool can't read the key
# ./tools/test_upload_rsa_key.sh
./tools/test_delete_key.sh

./tools/general_test.sh