#!/bin/sh

echo ""
echo "[*] PIP requirements"
pip3 install pycrypto argon2 lz4

echo ""
echo "[*] Python lib install"
sudo python3 ./setup.py install

echo ""
echo "[*] CLI tool setup"
cwd=$(echo $PWD)
cd / #Escape direnv $HOME relocalisation (see homesweethome project)
rm -f $HOME/.local/bin/cantreadth1s
ln -s $cwd/cantreadth1s/cantreadth1s.py $HOME/.local/bin/cantreadth1s
