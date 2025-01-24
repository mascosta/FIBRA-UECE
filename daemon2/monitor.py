import asyncio
import ipaddress
import os
from pathlib import Path
from subprocess import Popen
from scapy.all import AsyncSniffer, IP, TCP

# Caminhos configuráveis
fibra_path = Path(os.getenv("FIBRA_PATH", "/opt/fibra"))
python_path = Path(os.getenv("PYTHON_PATH", "/usr/bin/python3"))

# Função para acionar o Manager
def trigger_manager(src_ip):
    try:
        # Aciona o script manager.py passando o IP como argumento
        Popen([str(python_path), str(fibra_path / "manager.py"), src_ip])
    except Exception as e:
        # Apenas imprime o erro, sem registrar em logs para evitar sobrecarga
        print(f"Erro ao acionar o Manager para o IP {src_ip}: {e}")

# Processa conexões TCP
async def handle_incoming_connection(packet):
    try:
        if not (IP in packet and TCP in packet):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Ignora pacotes com IPs privados ou sem destino
        if ipaddress.ip_address(src_ip).is_private or not dst_ip:
            return

        # Verifica flag SYN sem ACK
        if 'S' in packet[TCP].flags and not 'A' in packet[TCP].flags:
            # Aciona o manager para processar o IP
            trigger_manager(src_ip)
    except Exception as e:
        # Apenas imprime o erro, sem registrar em logs
        print(f"Erro ao processar pacote: {e}")

# Captura de pacotes
async def packet_sniffer():
    try:
        # Inicia o sniffer assíncrono
        sniffer = AsyncSniffer(
            filter="tcp",
            prn=lambda pkt: asyncio.create_task(handle_incoming_connection(pkt))
        )
        sniffer.start()
        await asyncio.sleep(float("inf"))
    except Exception as e:
        # Apenas imprime o erro, já que não há logs configurados
        print(f"Erro crítico na captura de pacotes: {e}")

if __name__ == "__main__":
    asyncio.run(packet_sniffer())