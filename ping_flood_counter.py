#!/usr/bin/env python3
import socket
import struct
import time
import threading
import ipaddress
import random
from scapy.all import *

# Constants
FLOOD_THRESHOLD = 5  # Number of packets per second to consider as flooding
COUNTER_ATTACK_DURATION = 30  # Duration of counter-attack in seconds
PACKET_SIZE = 64  # Size of ICMPv6 packets

class PingFloodCounter:
    def __init__(self):
        self.attackers = {}  # Dictionary to track potential attackers
        self.lock = threading.Lock()
        self.running = True

    def create_icmpv6_packet(self, src_ip, dst_ip, payload=None):
        """Create an ICMPv6 Echo Request packet with custom headers"""
        if payload is None:
            payload = b'X' * (PACKET_SIZE - 8)  # 8 bytes for ICMPv6 header

        # Create IPv6 header
        ipv6 = IPv6(
            src=src_ip,
            dst=dst_ip,
            nh=58  # ICMPv6 protocol number
        )

        # Create ICMPv6 Echo Request
        icmpv6 = ICMPv6EchoRequest(
            id=random.randint(0, 65535),
            seq=random.randint(0, 65535),
            data=payload
        )

        return ipv6/icmpv6

    def monitor_traffic(self):
        def handle_pkt(pkt):
            if pkt.haslayer(ICMPv6EchoRequest):
                src_ip = pkt[IPv6].src
                current_time = time.time()

                with self.lock:
                    if src_ip not in self.attackers:
                        self.attackers[src_ip] = {'count': 1, 'first_seen': current_time}
                    else:
                        self.attackers[src_ip]['count'] += 1

                        time_diff = current_time - self.attackers[src_ip]['first_seen']
                        if time_diff >= 1.0:
                            rate = self.attackers[src_ip]['count'] / time_diff
                            print(f"[DEBUG] {src_ip} -> Rate: {rate:.2f} packets/sec")
                            if rate >= FLOOD_THRESHOLD:
                                print(f"Flood attack detected from {src_ip}! Rate: {rate:.2f} packets/sec")
                                print(f"[DEBUG] Flood detected from {src_ip}. Executing counter-attack...")
                                self.counter_attack(src_ip)
                                self.attackers[src_ip] = {'count': 0, 'first_seen': current_time}
                            self.attackers[src_ip] = {'count': 0, 'first_seen': current_time}

        print("[*] Sniffing ICMPv6 Echo Requests on wlan0...")
        sniff(iface="wlan0", filter="icmp6 and ip6", prn=handle_pkt, store=0)

    def counter_attack(self, attacker_ip):
        print(f"Launching counter-attack against {attacker_ip}")
        print(f"[DEBUG] Flood detected from {attacker_ip}. Executing counter-attack...")

        if attacker_ip.startswith("fe80::"):
            attacker_ip += "%wlan0"

        local_ip = self.get_local_ipv6()
        print(f"Using source IP: {local_ip}")

        # Get MAC address of interface
        iface = "wlan0"
        try:
            attacker_mac = getmacbyip6(attacker_ip)
            src_mac = get_if_hwaddr(iface)
        except Exception as e:
            print(f"Failed to resolve MAC: {e}")
            return

        for _ in range(100):
            ipv6 = IPv6(src=local_ip, dst=attacker_ip)
            icmp = ICMPv6EchoRequest(id=random.randint(0, 65535), seq=random.randint(0, 65535))
            pkt = Ether(src=src_mac, dst=attacker_mac) / ipv6 / icmp
            sendp(pkt, iface=iface, verbose=0)
            time.sleep(0.001)



    def get_local_ipv6(self):
        """Get local IPv6 address"""
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect(('2001:4860:4860::8888', 80))  # Google's IPv6 DNS
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return '::1'  # Fallback to localhost

    def start(self):
        """Start the monitoring and counter-attack system"""
        print("Starting Ping Flood Counter Attack system...")
        monitor_thread = threading.Thread(target=self.monitor_traffic)
        monitor_thread.daemon = True
        monitor_thread.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
            self.running = False
            monitor_thread.join()

if __name__ == "__main__":
    counter = PingFloodCounter()
    counter.start() 