#!/usr/bin/env python3
import socket
import struct
import time
import threading
import ipaddress
import random
from scapy.all import *
from scapy.layers.l2 import Ether # Ensure Ether is imported
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6ND_NA # Ensure these are imported
from scapy.all import get_if_list
# Constants
FLOOD_THRESHOLD = 5  # Number of packets per second to consider as flooding
COUNTER_ATTACK_DURATION = 30  # Duration of counter-attack in seconds
PACKET_SIZE = 64  # Size of ICMPv6 packets
current_device = 'enp4s0'

# Modified resolve_link_local_mac to use manual NDP
def resolve_link_local_mac(ipv6, iface, timeout=2):
    # Ensure it's a clean IP without scope for internal processing
    ipv6_clean = ipv6.split('%')[0]
    original_ipv6 = ipv6 # Keep original for error messages

    try:
        addr = ipaddress.IPv6Address(ipv6_clean)
        
        # If it's a global (non-link-local) address, getmacbyip6 should work fine
        # We'll use it as a fallback for non-link-local, or you could manually implement ARP for IPv4 / NDP for global IPv6
        if not addr.is_link_local:
            print(f"[DEBUG] Processing global IPv6: {ipv6_clean}. Using getmacbyip6.")
            mac = getmacbyip6(ipv6_clean)
            if mac:
                return ipv6_clean, mac # No scope needed for global addresses when returning
            else:
                raise RuntimeError(f"Could not resolve MAC for global IPv6 {ipv6_clean}.")

        # For link-local addresses, proceed with manual NDP
        target_ipv6_with_scope = f"{ipv6_clean}%{iface}"
        print(f"[DEBUG] Performing manual NDP for link-local IPv6: {target_ipv6_with_scope}")

        # Construct Neighbor Solicitation packet
        # Dest MAC for NS is the IPv6mcast address for Solicited-Node multicast group
        # Source IP for NS is usually unspecified address (::) or a valid unicast address on the interface
        # The solicited-node multicast address is ff02::1:ffXX:XXXX where XX:XXXX are the last 24 bits of the target IPv6
        solicited_node_multicast_group = f"ff02::1:ff{ipv6_clean.split(':')[-1]}"

        ns_pkt = Ether(dst="33:33:00:00:00:01") / \
                 IPv6(src="::", dst=solicited_node_multicast_group) / \
                 ICMPv6ND_NS(tgt=ipv6_clean)

        # Send Neighbor Solicitation and wait for Neighbor Advertisement
        # srp sends at layer 2 and receives responses
        ans, unans = srp(ns_pkt, iface=iface, timeout=timeout, verbose=0)

        for sent, received in ans:
            # Check if the received packet is a Neighbor Advertisement and targets our solicited IP
            if received.haslayer(ICMPv6ND_NA) and received[ICMPv6ND_NA].tgt == ipv6_clean:
                resolved_mac = received.src # Source MAC of the NA packet is the target's MAC
                print(f"[DEBUG] Manually resolved MAC for {target_ipv6_with_scope}: {resolved_mac}")
                return target_ipv6_with_scope, resolved_mac # Return the scoped IP and its MAC
        
        raise RuntimeError(f"Could not resolve MAC for {target_ipv6_with_scope} via manual NDP. "
                           "Ensure the host is online and reachable.")

    except ValueError:
        raise ValueError(f"Invalid IPv6 address string '{original_ipv6}' passed to resolve_link_local_mac.")
    except Scapy_Exception as e:
        # Catch Scapy-specific exceptions (e.g., interface issues, permissions)
        raise RuntimeError(f"Scapy error during MAC resolution (manual NDP): {e}")
    except Exception as e:
        # Catch any other unexpected errors
        raise RuntimeError(f"An unexpected error occurred during MAC resolution (manual NDP): {e}")

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

        print("[*] Sniffing ICMPv6 Echo Requests on " + current_device)
        sniff(iface=current_device, filter="icmp6 and ip6", prn=handle_pkt, store=0)

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

    def counter_attack(self, attacker_ip):
        print(f"Launching counter-attack against {attacker_ip}")
        print(f"[DEBUG] Flood detected from {attacker_ip}. Executing counter-attack...")

        local_ip = self.get_local_ipv6()
        print(f"Using source IP: {local_ip}")

        iface = current_device
        try:
            # This call remains the same, but the internal logic of resolve_link_local_mac has changed
            attacker_ip_for_packet, attacker_mac = resolve_link_local_mac(attacker_ip, iface)
            src_mac = get_if_hwaddr(iface)
        except Exception as e:
            print(f"Failed to resolve MAC: {e}")
            return

        print(f"[DEBUG] Resolved attacker_ip for packet: {attacker_ip_for_packet}, MAC: {attacker_mac}")
        print(f"[DEBUG] Source MAC: {src_mac}")

        for _ in range(100):
            ipv6 = IPv6(src=local_ip, dst=attacker_ip_for_packet)
            icmp = ICMPv6EchoRequest(id=random.randint(0, 65535), seq=random.randint(0, 65535))
            pkt = Ether(src=src_mac, dst=attacker_mac) / ipv6 / icmp
            sendp(pkt, iface=iface, verbose=0)
            time.sleep(0.001)

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
    scapy_iface_name = None
    for iface_str in get_if_list():
        if iface_str.startswith('enp4s0'): # Use startswith in case of slight variations
            scapy_iface_name = iface_str
            break

    if scapy_iface_name:
        current_device = scapy_iface_name
        print(f"[DEBUG] Updated current_device to canonical Scapy name: {current_device}")
    else:
        print("[WARNING] Could not find 'enp4s0' in Scapy's interface list. Proceeding with original name.")