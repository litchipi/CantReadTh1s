#!/bin/bash

compressions="lzma bz2 zlib lz4 none"
for cmp in $compressions
do
    echo $cmp
    cantreadth1s -v -c $cmp -p testpassword testdir
    cantreadth1s -v -p testpassword testdir_zipfile.cant_read_this
    echo ""
    echo ""
done

exit 0
rm -rf testdir
mkdir testdir
echo "tototata" > testdir/testfile0
echo $(python -c 'import random; print("".join([chr(random.randrange(ord("a"), ord("z"))) for i in range(5000000)]))') > testdir/testfile1


for cmp in $compressions
do
    echo $cmp
    inisum=$(sha256sum testdir/* 2>/dev/null)
    cantreadth1s -v -c $cmp -p testpassword testdir
    rm -rf testdir
    cantreadth1s -v -p testpassword testdir_zipfile.cant_read_this
    echo $inisum
    finsum=$(sha256sum testdir/* 2>/dev/null)
    echo $finsum
    echo ""
    read
done
