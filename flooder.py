from scapy.all import IPv6, ICMPv6EchoRequest, send
import time

victim = "fe80::affd:e2f4:cdd5:d337%wlan0"
iface = "wlan0"
for i in range(100):
    pkt = IPv6(dst=victim)/ICMPv6EchoRequest()
    send(pkt, iface=iface, verbose=0)
    time.sleep(0.01)  # Envia ~100 pacotes em 1 segundo
