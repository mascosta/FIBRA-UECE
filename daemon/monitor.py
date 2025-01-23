import psycopg2
import datetime
import ipaddress
import logging
import os
import asyncio
from scapy.all import AsyncSniffer, IP, TCP
from geoip2.database import Reader
from pathlib import Path
from subprocess import Popen
from logger import get_logger
from functools import lru_cache

# Configuração de Conexão
db_host = 'localhost'
db_name = 'firewall'
db_user = 'admin'
db_password = 'Q1w2e3r4'

fibraPath = Path(os.getenv("FIBRA_PATH", "/default/path"))
pythonPath = Path(os.getenv("PYTHON_PATH", "/default/python/path"))

# Configuração de logs
logger = get_logger("monitor", severity=logging.INFO)

# Cache para geolocalização
@lru_cache(maxsize=1000)
def get_geo_info(ip_address):
    try:
        with Reader('/usr/share/GeoIP/GeoLite2-City.mmdb') as reader:
            response = reader.city(ip_address)
            return {
                "country_code": response.country.iso_code,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
            }
    except Exception as e:
        logger.error(f"Erro ao obter informações de geolocalização para {ip_address}: {e}")
        return {"country_code": None, "city": None, "latitude": None, "longitude": None}

# Função para criar conexão com banco
def connect_db():
    try:
        conn = psycopg2.connect(host=db_host, dbname=db_name, user=db_user, password=db_password)
        return conn, conn.cursor()
    except Exception as e:
        logger.critical(f"Erro ao conectar ao banco de dados: {e}")
        raise

# Função para carregar whitelist na inicialização
def load_whitelist(cur):
    try:
        cur.execute("SELECT ip_address FROM wl_address_local")
        whitelist = {row[0] for row in cur.fetchall()}
        logger.info(f"Whitelist carregada com {len(whitelist)} IPs.")
        return whitelist
    except Exception as e:
        logger.error(f"Erro ao carregar whitelist: {e}")
        return set()

# Verifica se o IP está em listas e rastreia whitelist
def is_ip_allowed(cur, ip, processed_whitelist):
    try:
        if ip in processed_whitelist:
            return True  # Já processado

        # Verifica whitelist
        cur.execute("SELECT 1 FROM wl_address_local WHERE ip_address = %s", (ip,))
        if cur.fetchone():
            logger.info(f"IP {ip} está na whitelist. Ignorando processamento.")
            processed_whitelist.add(ip)
            return True

        # Verifica blacklist e tarpit
        for table in ["bl_address_local", "tp_address_local"]:
            cur.execute(f"SELECT 1 FROM {table} WHERE ip_address = %s", (ip,))
            if cur.fetchone():
                logger.debug(f"IP {ip} encontrado em {table}.")
                return True

        return False
    except Exception as e:
        logger.error(f"Erro ao verificar listas para IP {ip}: {e}")
        return False

# Função para processar conexões
async def handle_incoming_connection(packet, conn, cur, processed_whitelist):
    try:
        if not (IP in packet and TCP in packet):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Verifica se o IP de destino é válido
        if not dst_ip:
            logger.error(f"Pacote com IP de destino inválido: {packet.summary()}")
            return

        # Verifica e ignora IPs privados
        if ipaddress.ip_address(src_ip).is_private:
            return

        # Verifica se o IP está em listas
        if is_ip_allowed(cur, src_ip, processed_whitelist):
            return

        # Geolocalização
        geo_src = get_geo_info(src_ip)
        geo_dst = get_geo_info(dst_ip)

        # Se flag SYN sem ACK
        if 'S' in packet[TCP].flags and not 'A' in packet[TCP].flags:
            timestamp = datetime.datetime.now()
            cur.execute("""
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
        Popen([str(pythonPath), str(fibraPath / "manager.py"), src_ip])
    except Exception as e:
        logger.error(f"Erro ao acionar o Manager: {e}")

# Envolve a corrotina em uma função síncrona
def sync_wrapper(packet, conn, cur, processed_whitelist, loop):
    asyncio.run_coroutine_threadsafe(handle_incoming_connection(packet, conn, cur, processed_whitelist), loop)

# Captura de pacotes
async def packet_sniffer():
    conn, cur = connect_db()
    processed_whitelist = load_whitelist(cur)  # Carrega whitelist ao iniciar
    loop = asyncio.get_event_loop()
    logger.info("Iniciando captura de pacotes.")
    sniffer = AsyncSniffer(
        filter="tcp",
        prn=lambda pkt: sync_wrapper(pkt, conn, cur, processed_whitelist, loop)
    )
    sniffer.start()
    await asyncio.sleep(float("inf"))

if __name__ == "__main__":
    asyncio.run(packet_sniffer())
