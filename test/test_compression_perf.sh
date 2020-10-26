#!/bin/bash

DEBUG= #"-D"
OPTS="$DEBUG -p tata -v"

echo "[*] Generating large file to process ..."
#:find /usr/ > ./testfile
dmesg > ./testfile

clear

for cmp in lzma bz2 zlib lz4 none
do
    echo -e "\n\n\n$cmp"

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

    rm testfile testfile.crt
    mv testfile_original testfile
done
