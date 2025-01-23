import asyncio
import datetime
import ipaddress
import logging
from pathlib import Path
from subprocess import Popen
from functools import lru_cache
from scapy.all import AsyncSniffer, IP, TCP
from db_config import get_db_connection
from geo_helper import get_geo_info
from logger import get_logger

# Configuração de logs
logger = get_logger("monitor", severity=logging.INFO)

# Caminho dos scripts
fibra_path = Path(os.getenv("FIBRA_PATH", "/default/path"))
python_path = Path(os.getenv("PYTHON_PATH", "/usr/bin/python3"))

# Função para carregar whitelist na inicialização
def load_whitelist(cursor):
    try:
        cursor.execute("SELECT ip_address FROM wl_address_local")
        whitelist = {row[0] for row in cursor.fetchall()}
        logger.info(f"Whitelist carregada com {len(whitelist)} IPs.")
        return whitelist
    except Exception as e:
        logger.error(f"Erro ao carregar whitelist: {e}")
        return set()

# Verifica se o IP está em listas e rastreia whitelist
def is_ip_allowed(cursor, ip, processed_whitelist):
    try:
        if ip in processed_whitelist:
            return True  # Já processado

        # Verifica whitelist
        cursor.execute("SELECT 1 FROM wl_address_local WHERE ip_address = %s", (ip,))
        if cursor.fetchone():
            logger.info(f"IP {ip} está na whitelist. Ignorando processamento.")
            processed_whitelist.add(ip)
            return True

        # Verifica blacklist e tarpit
        for table in ["bl_address_local", "tp_address_local"]:
            cursor.execute(f"SELECT 1 FROM {table} WHERE ip_address = %s", (ip,))
            if cursor.fetchone():
                logger.debug(f"IP {ip} encontrado em {table}.")
                return True

        return False
    except Exception as e:
        logger.error(f"Erro ao verificar listas para IP {ip}: {e}")
        return False

# Função para processar conexões
async def handle_incoming_connection(packet, conn, cursor, processed_whitelist):
    try:
        if not (IP in packet and TCP in packet):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Verifica se o IP de destino é válido
        if not dst_ip or ipaddress.ip_address(src_ip).is_private:
            return

        # Verifica se o IP está em listas
        if is_ip_allowed(cursor, src_ip, processed_whitelist):
            return

        # Geolocalização
        geo_src = get_geo_info(src_ip)
        geo_dst = get_geo_info(dst_ip)

        # Se flag SYN sem ACK
        if 'S' in packet[TCP].flags and not 'A' in packet[TCP].flags:
            timestamp = datetime.datetime.now()
            cursor.execute("""
                INSERT INTO network_traffic (
                    timestamp, src_ip, dst_ip, protocol_name,
                    src_country_code, src_city, src_latitude, src_longitude,
                    dst_country_code, dst_city, dst_latitude, dst_longitude
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                timestamp, src_ip, dst_ip, 'TCP',
                geo_src["country_code"], geo_src["city"], geo_src["latitude"], geo_src["longitude"],
                geo_dst["country_code"], geo_dst["city"], geo_dst["latitude"], geo_dst["longitude"]
            ))
            conn.commit()
            logger.info(f"Conexão SYN de {src_ip} para {dst_ip} registrada.")
            trigger_manager(src_ip)
    except Exception as e:
        logger.error(f"Erro ao processar pacote: {e}")

# Função para acionar Manager
def trigger_manager(src_ip):
    try:
        logger.info(f"Acionando o Manager para o IP: {src_ip}")
        Popen([str(python_path), str(fibra_path / "manager.py"), src_ip])
    except Exception as e:
        logger.error(f"Erro ao acionar o Manager: {e}")

# Envolve a corrotina em uma função síncrona
def sync_wrapper(packet, conn, cursor, processed_whitelist, loop):
    asyncio.run_coroutine_threadsafe(handle_incoming_connection(packet, conn, cursor, processed_whitelist), loop)

# Captura de pacotes
async def packet_sniffer():
    conn, cursor = get_db_connection(), None
    try:
        cursor = conn.cursor()
        processed_whitelist = load_whitelist(cursor)  # Carrega whitelist ao iniciar
        loop = asyncio.get_event_loop()
        logger.info("Iniciando captura de pacotes.")
        sniffer = AsyncSniffer(
            filter="tcp",
            prn=lambda pkt: sync_wrapper(pkt, conn, cursor, processed_whitelist, loop)
        )
        sniffer.start()
        await asyncio.sleep(float("inf"))
    except Exception as e:
        logger.critical(f"Erro crítico na captura de pacotes: {e}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    asyncio.run(packet_sniffer())
