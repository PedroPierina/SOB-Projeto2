#!/bin/bash

device=`losetup -f`
cd ..
echo "Linking file.img to device $device."

losetup $device file.img

echo "Creating File System Minix on $device."
mkfs.minix $device 10000

mkdir device
echo "Mounting $device into `pwd`/device."
mount -t minix $device ./device

echo "Lembrando que no momento da montagem se não havia um módulo de minix no sistema o default está sendo usado"
