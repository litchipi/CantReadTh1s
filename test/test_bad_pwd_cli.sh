DEBUG= #"-D"

GOOD_PWD="tata"
WRONG_PWD="toto"
OPTS="$DEBUG -v"

clear

./.generate_test.py 8192 ./testfile
testfilesum=$(shasum ./testfile)
for cmp in lzma bz2 zlib lz4 none
do
    echo -e "\n\n\n$cmp"

    echo "[*] Process"
    if ! cantreadth1s $OPTS -c $cmp -p $GOOD_PWD ./testfile ; then
        echo $?
        exit 1
    fi

    echo -e "\n[*] Load"
    if cantreadth1s $OPTS -p $WRONG_PWD ./testfile.crt ; then
        exit 1
    fi

    if [[ $(shasum ./testfile) != $testfilesum ]]; then
        echo "Testfile checksum doesn't match"
        exit 1
    fi
    rm testfile.crt
done
rm testfile
