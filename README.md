# Ping Flood Counter Attack

Este programa implementa um sistema de detecção e contra-ataque para ataques do tipo Ping Flood usando ICMPv6.

## Requisitos

- Python 3.6 ou superior
- Scapy
- Permissões de root/administrador (para usar sockets raw)

## Instalação

1. Instale as dependências:
```bash
pip install -r requirements.txt
```

2. Execute o programa com privilégios de administrador:
```bash
sudo python3 ping_flood_counter.py
```

## Funcionalidades

- Monitora o tráfego de rede para detectar ataques ICMPv6 Echo Request
- Identifica ataques de flooding (mais de 10 pacotes por segundo)
- Realiza contra-ataque usando IP spoofing
- Implementa DDoS contra o atacante

## Observações

- O programa deve ser executado com privilégios de administrador
- A interface de rede padrão é 'eth0'. Se sua interface for diferente, modifique o código
- O threshold de flooding pode ser ajustado alterando a constante `FLOOD_THRESHOLD`
- Use com responsabilidade e apenas em ambientes controlados 