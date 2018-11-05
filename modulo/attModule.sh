#!/bin/bash
clear
echo -e "Makefile"
make

echo -e "Removendo modulo"
rmmod cryptomodule

echo -e "Inserindo modulo"
insmod cryptomodule.ko keyHex=''