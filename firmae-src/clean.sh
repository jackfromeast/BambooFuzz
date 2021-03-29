#!/bin/bash
chmod -R 777 ./  
chown -R root ./
umount ./scratch/1/image > /dev/null
sudo ip link set tap1_0 down
sudo ip link delete tap1_0.1
sudo tunctl -d tap1_0
