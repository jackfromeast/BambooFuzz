#!/bin/bash
set -e
set -u

if [ -e ./firmae.config ]; then
    source ./firmae.config
elif [ -e ../firmae.config ]; then
    source ../firmae.config
elif [ -e ../../firmae.config ]; then
    source ../../firmae.config
else
    echo "Error: Could not find 'firmae.config'!"
    exit 1
fi

if [ $# != 1 ];then
 echo "input IID"
else
DEVICE=`add_partition "/home/dilision/FirmAE/scratch/${1}/image.raw"` #进行关联创建设备
mount ${DEVICE} /home/dilision/FirmAE/scratch/${1}/image > /dev/null 
echo "waiting for your make"                   # 参数-n的作用是不换行，echo默认换行
read  name
umount /home/dilision/FirmAE/scratch/${1}/image > /dev/null
del_partition ${DEVICE:0:$((${#DEVICE}-2))}#取消关联移除设备移除设备
fi
