#!/bin/bash
# usage: sudo ./capture_normal.sh normal_1.pcap
OUT=$1
timeout 120 tcpdump -i listener -w $OUT >/dev/null 2>&1 &
ip netns exec client ping -i 0.2 -c 600 10.0.0.1 >/dev/null 2>&1 &
sleep 40
ip netns exec client wpa_cli -i phone disconnect; sleep 2
ip netns exec client wpa_cli -i phone reconnect
sleep 40
ip netns exec client wpa_cli -i phone disconnect; sleep 2
ip netns exec client wpa_cli -i phone reconnect
wait
chown $SUDO_USER $OUT
echo "saved $OUT"
