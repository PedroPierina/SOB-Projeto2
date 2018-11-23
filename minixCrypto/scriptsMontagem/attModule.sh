#!/bin/bash
clear
cd ..
echo -e "Umount Device"
umount device

echo -e "Remove Device"
rm -rf device

echo -e "Makefile"
make > auxattmodule.txt

cat auxattmodule.txt

# Se error parar execução
if grep -q "error:" auxattmodule.txt
then
    make clean
    echo "Erro no makefile"
else
    echo -e "movendo modulo"
    rmmod minix

    echo -e "Inserindo modulo"

    insmod minix.ko key="31313131313131313131313131313131"
    
    cd scriptsMontagem
    bash createFS.sh
    cd ..

    cp test.txt ./device
fi

rm auxattmodule.txt
