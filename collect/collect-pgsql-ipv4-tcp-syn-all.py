from scapy.all import sniff, IP, TCP
from geoip2.database import Reader
import psycopg2
import datetime

# Configuração do PostgreSQL
db_host = 'localhost'
db_name = 'firewall'
db_user = 'admin'
db_password = 'Q1w2e3r4'

# Conexão ao banco de dados
conn = psycopg2.connect(host=db_host, dbname=db_name, user=db_user, password=db_password)
cur = conn.cursor()

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
    # Adicione mais conforme necessário
}

# Função para obter as informações de protocolo
def get_protocol_info(packet):
    protocol_code = packet[IP].proto
    protocol_name = protocol_mapping.get(protocol_code, 'Unknown')
    return protocol_code, protocol_name

# Função para obter as informações de serviço
def get_service_info(packet):
    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport
    src_service = service_mapping.get(src_port, 'Unknown')
    dst_service = service_mapping.get(dst_port, 'Unknown')
    return src_service, dst_service

# Função para obter latitude, longitude e country code
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
        print(f"Error getting geo info for {ip_address}: {e}")
        return None, None, None, None

# Função para inserir dados no banco de dados PostgreSQL
def insert_data(src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_lat, src_lon, dst_country_code, dst_city, dst_lat, dst_lon, src_port, dst_port):
    timestamp = datetime.datetime.now()
    query = """
    INSERT INTO network_traffic (timestamp, src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_latitude, src_longitude, dst_country_code, dst_city, dst_latitude, dst_longitude, src_port, dst_port)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
    """
    cur.execute(query, (timestamp, src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_lat, src_lon, dst_country_code, dst_city, dst_lat, dst_lon, src_port, dst_port))
    conn.commit()

def handle_incoming_connection(packet):
    if not (IP in packet and TCP in packet):
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    protocol_code, protocol_name = get_protocol_info(packet)
    src_service, dst_service = get_service_info(packet)

    src_country_code, src_city, src_lat, src_lon = get_geo_info(src_ip)
    dst_country_code, dst_city, dst_lat, dst_lon = get_geo_info(dst_ip)

    src_port = packet[TCP].sport
    dst_port = packet[TCP].dport

    # Inserção condicionada à identificação como uma tentativa de conexão (flag SYN sem ACK)
    if 'S' in packet[TCP].flags and not 'A' in packet[TCP].flags:
        insert_data(src_ip, dst_ip, protocol_name, src_service, dst_service, src_country_code, src_city, src_lat, src_lon, dst_country_code, dst_city, dst_lat, dst_lon, src_port, dst_port)

# Callback para processamento de cada pacote capturado
def packet_callback(packet):
    handle_incoming_connection(packet)

# Inicia a captura de pacotes em tempo real, com foco em tráfego TCP
sniff(prn=packet_callback, store=0, filter="tcp")
