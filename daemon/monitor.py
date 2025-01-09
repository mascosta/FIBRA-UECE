import psycopg2
import datetime
import ipaddress
import logging
import os
from scapy.all import sniff, IP, TCP
from geoip2.database import Reader
from time import time
from pathlib import Path
from subprocess import Popen
from logger import get_logger

# Configuração do PostgreSQL
db_host = 'localhost'
db_name = 'firewall'
db_user = 'admin'
db_password = 'Q1w2e3r4'

fibraPath = Path(os.getenv("FIBRA_PATH", "/default/path"))
pythonPath = Path(os.getenv("PYTHON_PATH", "/default/python/path"))

# Conexão ao banco de dados
conn = psycopg2.connect(host=db_host, dbname=db_name, user=db_user, password=db_password)
cur = conn.cursor()

# Configuração de logs
logger = get_logger("monitor", severity=logging.DEBUG)

# Mapeamento de códigos de protocolo para nomes conhecidos de serviços
protocol_mapping = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    58: 'ICMPv6',
    88: 'EIGRP',
    89: 'OSPF',
    115: 'L2TP',
}

# Mapeamento de portas para nomes conhecidos de serviços
service_mapping = {
    20: 'FTP Data',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    67: 'DHCP Server',
    68: 'DHCP Client',
    80: 'HTTP',
    110: 'POP3',
    123: 'NTP',
    143: 'IMAP',
    161: 'SNMP',
    443: 'HTTPS',
    3389: 'RDP',
    5060: 'SIP',
}

# Função para obter informações de protocolo
def get_protocol_info(packet):
    protocol_code = packet[IP].proto
    protocol_name = protocol_mapping.get(protocol_code, 'Unknown')
    return protocol_code, protocol_name

# Função para obter informações de serviço
def get_service_info(packet):
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    src_service = service_mapping.get(src_port, 'Unknown')
    dst_service = service_mapping.get(dst_port, 'Unknown')
    return src_service, dst_service

# Função para obter informações de geolocalização
def get_geo_info(ip_address):
    try:
        with Reader('/usr/share/GeoIP/GeoLite2-City.mmdb') as reader:
            response = reader.city(ip_address)
            country_code = response.country.iso_code
            city = response.city.name
            latitude = response.location.latitude
            longitude = response.location.longitude
            return country_code, city, latitude, longitude
    except Exception as e:
        logger.error(f"Erro ao obter informações de geolocalização para {ip_address}: {e}")
        return None, None, None, None

# Verifica se o IP é privado
def is_private_ip(ip):
    return ipaddress.ip_address(ip).is_private

# Verifica se o IP está em whitelist, blacklist ou tarpit
def is_ip_in_any_list(ip):
    try:
        start_time = time()

        # Verifica whitelist
        cur.execute("SELECT 1 FROM wl_address_local WHERE ip_address = %s", (ip,))
        if cur.fetchone():
            logger.debug(f"IP {ip} encontrado na whitelist.")
            return True

        # Verifica blacklist
        cur.execute("SELECT 1 FROM bl_address_local WHERE ip_address = %s", (ip,))
        if cur.fetchone():
            logger.debug(f"IP {ip} encontrado na blacklist.")
            return True

        # Verifica tarpit
        cur.execute("SELECT 1 FROM tp_address_local WHERE ip_address = %s", (ip,))
        if cur.fetchone():
            logger.debug(f"IP {ip} encontrado na tarpit.")
            return True

        elapsed_time = (time() - start_time) * 1000
        logger.debug(f"IP {ip} não encontrado em nenhuma lista. Tempo de verificação: {elapsed_time:.2f} ms.")
        return False
    except Exception as e:
        logger.error(f"Erro ao verificar listas para IP {ip}: {e}")
        return False

# Função principal para processar conexões
def handle_incoming_connection(packet):
    if not (IP in packet and TCP in packet):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Verifica e ignora IPs privados
    if is_private_ip(src_ip):
    #    logger.info(f"Endereço {src_ip} é privado. Ignorando processamento.")
        return

    # Verifica se o IP está em qualquer lista (whitelist, blacklist ou tarpit)
    if is_ip_in_any_list(src_ip):
        logger.info(f"IP {src_ip} está em whitelist, blacklist ou tarpit. Ignorando registro.")
        return

    protocol_code, protocol_name = get_protocol_info(packet)
    src_service, dst_service = get_service_info(packet)

    # Obtém informações de geolocalização
    src_country_code, src_city, src_lat, src_lon = get_geo_info(src_ip)
    dst_country_code, dst_city, dst_lat, dst_lon = get_geo_info(dst_ip)

    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    # Inserção para pacotes com flag SYN (sem ACK)
    if 'S' in packet[TCP].flags and not 'A' in packet[TCP].flags:
        start_time = time()
        insert_data(
            src_ip, dst_ip, protocol_name, src_service, dst_service,
            src_country_code, src_city, src_lat, src_lon,
            dst_country_code, dst_city, dst_lat, dst_lon,
            src_port, dst_port
        )
        elapsed_time = (time() - start_time) * 1000
        logger.debug(f"IP {src_ip} enviado ao banco de dados em {elapsed_time:.2f} ms.")
        trigger_manager(src_ip)

# Função para inserir dados no banco de dados
def insert_data(src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_lat, src_lon, dst_country_code, dst_city, dst_lat, dst_lon, src_port, dst_port):
    timestamp = datetime.datetime.now()
    query = """
    INSERT INTO network_traffic (timestamp, src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_latitude, src_longitude, dst_country_code, dst_city, dst_latitude, dst_longitude, src_port, dst_port)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
    """
    cur.execute(query, (timestamp, src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_lat, src_lon, dst_country_code, dst_city, dst_lat, dst_lon, src_port, dst_port))
    conn.commit()

# Função para acionar o Manager
def trigger_manager(src_ip):
    try:
        logger.info(f"Acionando o Manager para o IP: {src_ip}")
        Popen([pythonPath, fibraPath / "manager.py", src_ip])
    except Exception as e:
        logger.error(f"Erro ao acionar o Manager: {e}")

# Callback para processar pacotes capturados
def packet_callback(packet):
    handle_incoming_connection(packet)

# Inicia a captura de pacotes
logger.info("Iniciando captura de pacotes.")
sniff(prn=packet_callback, store=0, filter="tcp")
