#!/bin/bash

compressions="lzma bz2 zlib lz4 none"

mkdir -p testdir
echo "tototata" > testdir/testfile0
echo $(python -c 'import random; print("".join([chr(random.randrange(ord("a"), ord("z"))) for i in range(5000000)]))') > testdir/testfile1

for cmp in $compressions
do
    echo $cmp
    inisum=$(sha256sum testdir/* 2>/dev/null)
    cantreadth1s -c $cmp -o testdircrt.cant_read_this -p testpassword testdir
    rm -rf testdir
    cantreadth1s -p testpassword testdircrt.cant_read_this
    echo $inisum
    finsum=$(sha256sum testdir/* 2>/dev/null)
    echo $finsum
    echo ""
done
rm -rf testdircrt.cant_read_this testdir
