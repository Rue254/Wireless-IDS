#!/bin/bash
cd ~/wids
pkill hostapd; pkill wpa_supplicant
ip netns delete client 2>/dev/null
rmmod mac80211_hwsim 2>/dev/null
sleep 1
modprobe mac80211_hwsim radios=3
sleep 1
for i in wlan0 wlan1 wlan2; do
  nmcli device set $i managed no 2>/dev/null
  ip link set $i down
done
rfkill unblock all

# Give the three radios their real names
ip link set wlan0 name router
ip link set wlan1 name phone
ip link set wlan2 name listener

# Move the phone into its own space so its traffic really goes over the air
ip netns add client
PHY=$(iw dev phone info | awk '/wiphy/ {print "phy"$2}')
iw phy $PHY set netns name client

# Router starts
hostapd -B ap.conf
sleep 2
ip addr add 10.0.0.1/24 dev router

# Phone connects
ip netns exec client wpa_supplicant -B -i phone -c client.conf
sleep 5
ip netns exec client ip addr add 10.0.0.2/24 dev phone

# Listener goes into listening (monitor) mode on the router's channel
ip link set listener down
iw dev listener set type monitor
ip link set listener up
iw dev listener set channel 6

echo "=== TEST ==="
ip netns exec client ping -c 3 10.0.0.1
iw dev listener info | grep -E "type|channel"
