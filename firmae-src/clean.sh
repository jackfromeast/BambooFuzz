#!/bin/bash
chmod -R 777 ./  
chown -R root ./
if [ $# != 1 ];then
 echo "input IID"
else
umount ./scratch/${1}/image > /dev/null
sudo ip link set tap${1}_0 down
sudo ip link delete tap${1}_0
sudo ip link delete tap${1}_0.1
sudo tunctl -d tap${1}_0
pid= ps-a | grep qemu | awk {'print $2'}
kill ${pid}
fi
