#!/bin/bash

set -e 
cd $(dirname $0)/..

echo "Getting newer version"

./install.sh

cd ./test/

for f in $(ls test_*);
do
    clear
    echo "Test $f"
    ./$f
    echo "Test $f finished"
    echo -e "\nPress enter to launch next test"
    read
done;
