#!/bin/bash

begin=$1
end=$2

for l in [${begin}..${end}]
do
losetup -d /dev/loop$l
done
