#!/bin/sh

pip3 install pycrypto
cwd=$(echo $PWD)
cd / #Escape direnv HOME redirection (see homesweethome project)
ln -s $cwd/cantreadth1s/cantreadth1s.py $HOME/.local/bin/cantreadth1s
