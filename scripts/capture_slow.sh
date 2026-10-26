#!/bin/bash
# usage: sudo ./capture_slow.sh attack_slow_1.pcap 5
OUT=$1; RATE=$2
timeout 90 tcpdump -i listener -w $OUT >/dev/null 2>&1 &
ip netns exec client ping -i 0.2 -c 450 10.0.0.1 >/dev/null 2>&1 &
sleep 30
/home/kali/wids/.venv/bin/python slow_deauth.py $RATE
wait
chown $SUDO_USER $OUT
echo "saved $OUT"
