Pontifícia Universidade Católica do Rio Grande do Sul
Escola Politécnica
Laboratório de Redes de Computadores
Ping Flood Counter Attack
Objetivo
O trabalho consiste em desenvolver um programa usando socket raw que possa identificar um
ataque do tipo ping flood e realize o contra-ataque usando técnicas como ICMPv6 flood, IP
spoofing e DDoS.
Descrição
O ataque deve ser implementado da seguinte:
1) Intruso: envia mensagens do tipo ICMPv6 Echo Request para as máquinas da rede. Para
a máquina a ser atacada deverá enviar a mensagem em flooding. Essa mensagem pode
ser gerada com o utilitário ping;
2) Servidor na máquina atacada:
a. monitora quais máquinas enviam ICMPv6 de Echo Request para uma máquina
local e cria uma lista destas máquinas;
b. se identificar que uma máquina está enviando um ICMPv6 Echo request em
flooding, deverá contra atacar. O contra-ataque deve enviar mensagens de
ICMPv6 Echo Request em flooding para o atacante, sendo que o IP de origem da
mensagem deve ser o IP da máquina que iniciou o ataque, implementando
assim um IP spoofing. O contra-ataque deve fazer um DDoS, ativando o envio de
mensagens de ICMPv6 Echo Request em flooding a partir de outros hosts na
subrede.
Observações:
1. O Servidor deve ser implementado utilizando socket raw para envio e recebimento dos
pacotes ICMPv6.
2. Os pacotes devem ter seus headers de nível 2 (Ethernet) e 3 (IPv6) totalmente
preenchidos pelo programa, bem como o header do protocolo ICMPv6. Não serão
aceitos trabalhos em que os headers fiquem sob controle da pilha de protocolos do
Sistema Operacional.
Resultados e Entrega
Grupos: máximo 3 alunos.
Entrega:
1. Apresentação em aula.
2. Relatório descrevendo a implementação (upload no Moodle)
3. Código da implementação (upload no Moodle)
Data Entrega: 23/6
Apresentação: 23/6 e 30/6