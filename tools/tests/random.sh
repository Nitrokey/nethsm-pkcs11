#!/bin/sh -x

rm -rf _data _data2

# generate two random files, and compare them to make sure they are 
# return 1 if they are the same, 0 if they are different

pkcs11-tool --module target/debug/libnethsm_pkcs11.so --generate-random 32 --output-file _data
if [ $? -ne 0 ]; then
    exit $?
fi

pkcs11-tool --module target/debug/libnethsm_pkcs11.so --generate-random 32 --output-file _data2
if [ $? -ne 0 ]; then
    exit $?
fi


# ensure they are different
diff _data _data2 && exit 1
exit 0