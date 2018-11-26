#!/bin/bash

echo "ARQUIVO NORMAL -------------------------------------------------------------"
cat grandeteste.txt
cd minixCrypto/scriptsMontagem/ 
./cleanEverything.sh
./attModule.sh
cd ../..
cp grandeteste.txt device/
echo "ARQUIVO COMO MINIX MODIFICADO ---------------------------------------------"
cat device/grandeteste.txt
umount device/
rmmod minix
mount file.img device/
echo "ARQUIVO COM MINIX PADRÂO --------------------------------------------------"
cat device/grandeteste.txt
