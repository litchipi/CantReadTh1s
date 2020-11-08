#!/bin/bash

DEBUG= #"-D"
SECLEVEL=50
OPTS="$DEBUG -p tata -v -s $SECLEVEL"

clear

echo "Testing with a security level of $SECLEVEL"

for cmp in lzma bz2 zlib lz4 none
do
    echo -e "\n\n\n$cmp"
    ./.generate_test.py 8192 ./testfile

    echo "[*] Process"
    if ! cantreadth1s $OPTS -c $cmp ./testfile ; then
        echo $?
        exit 1
    fi

    mv testfile testfile_original

    echo -e "\n[*] Load"
    if ! cantreadth1s $OPTS ./testfile.crt ; then
        exit 1
    fi

    sha256sum testfile testfile_original

    rm testfile testfile_original testfile.crt
done
