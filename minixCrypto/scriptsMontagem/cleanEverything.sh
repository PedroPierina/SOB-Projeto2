#!/bin/bash

cd ../..
rm device/*
umount device/
bash scriptsImportantes/cleanLoops.sh 0 20

cd minixCrypto
rm .*
rm *.o
rm *safe
rm *.ko
rm *.order
rm *.symvers
rm *.mod.*
rm -rf .tmp_versions/