#!/bin/sh

pip3 install pycrypto smaz-py3 argon2
cwd=$(echo $PWD)
cd / #Escape direnv $HOME relocalisation (see homesweethome project)
ln -s $cwd/cantreadth1s/cantreadth1s.py $HOME/.local/bin/cantreadth1s
