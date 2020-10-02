#!/bin/bash

compressions="lzma bz2 zlib lz4 none"

mkdir -p testdir
echo "tototata" > testdir/testfile0
echo $(python3 -c 'import random; print("".join([chr(random.randrange(ord("a"), ord("z"))) for i in range(50000)]))') > testdir/testfile1

DEBUG= #"-D"
OUTFILE="testdircrt.crt"
OPTS="$DEBUG -v -p totoazekfazlke"
for cmp in $compressions
do
    inisum=$(sha256sum testdir/* 2>/dev/null)
    echo -e "\n\n\n$cmp"
    if ! cantreadth1s $OPTS -o $OUTFILE -c $cmp testdir ; then
        exit 1
    fi
    rm -rf testdir
    echo ""
    if ! cantreadth1s $OPTS $OUTFILE ; then
        exit 1
    fi
    echo $inisum
    finsum=$(sha256sum testdir/* 2>/dev/null)
    echo $finsum
    echo ""
done
rm -rf $OUTFILE testdir
