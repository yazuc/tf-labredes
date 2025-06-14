from scapy.all import *

iface = "wlan0"
dst = "fe80::ec85:dfb9:5d06:a15c%wlan0"

for i in range(5):
    send(IPv6(dst=dst)/ICMPv6EchoRequest(), iface=iface)
