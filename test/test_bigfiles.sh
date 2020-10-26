#!/bin/bash

DEBUG= #"-D"
OPTS="$DEBUG -p tata -v -s 3"

for nb in 1 2 3 4 5 6 7 8 9 10 20 30 50 100 150 200 300 400 500 700 900
do
    clear
    for cmp in lzma bz2 zlib lz4 none
    do
        echo "[$nb] $cmp"
        dd if=/dev/urandom of=./testfile bs=1M count=$nb
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
done
