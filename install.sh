#!/bin/sh

echo ""
echo "[*] PIP requirements"
pip3 install pycrypto smaz-py3 argon2

echo ""
echo "[*] Python lib install"
sudo python3 ./setup.py install

echo ""
echo "[*] CLI tool setup"
cwd=$(echo $PWD)
cd / #Escape direnv $HOME relocalisation (see homesweethome project)
ln -s $cwd/cantreadth1s/cantreadth1s.py $HOME/.local/bin/cantreadth1s
