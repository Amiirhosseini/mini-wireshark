#!/bin/bash 

ip_in=$1
server_port=$2
device=$3
client_port=$4

ip4=$(/sbin/ip -o -4 addr list $device | awk '{print $4}' | cut -d/ -f1)
read MAC </sys/class/net/$device/address
default_mac=$(arp -n | grep `route -n | awk '/UG/{print $2}'` | awk '{print $3}')

echo $ip_in > infotest.txt
echo $server_port >> infotest.txt
echo $ip4 >> infotest.txt
echo $client_port >> infotest.txt
echo $device >> infotest.txt
echo $MAC >> infotest.txt
echo $default_mac >> infotest.txt