import requests
import os
import logging
import sys
from ipaddress import ip_address
from db_config import get_db_connection
from geo_helper import get_geo_info
from logger import get_logger

# Configuração do logger
logger = get_logger("tarpit-in", severity=logging.INFO)
logger.info("Iniciando checagem de reputação de IPs.")

# Chave da API do AbuseIPDB
API_KEY = os.getenv('API_KEY')

if not API_KEY:
    logger.error("API_KEY não está configurada. Configure a variável de ambiente 'API_KEY' antes de executar o script.")
else:
    logger.debug(f"API_KEY carregada: {API_KEY[:5]}***")  # Exibe parte da chave para verificação

# Funções auxiliares
def is_private_ip(ip):
    """
    Verifica se o IP é privado.
    """
    return ip_address(ip).is_private

def execute_query(conn, query, params=()):
    """
    Executa uma consulta no banco de dados PostgreSQL.
    """
    try:
        with conn.cursor() as cur:
            cur.execute(query, params)
            if query.strip().lower().startswith("select"):
                return cur.fetchall()
            conn.commit()
    except Exception as e:
        logger.exception(f"Erro ao executar query: {query}")
        return []

def fetch_ip_reputation(ip):
    """
    Faz uma consulta à API do AbuseIPDB para buscar a reputação de um IP.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,  # Atualizado para refletir a documentação
        'verbose': True  # Adiciona informações detalhadas
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()['data']
        elif response.status_code == 401:
            logger.error("Erro 401: Chave de API inválida ou não configurada.")
        else:
            logger.error(f"Erro na API AbuseIPDB para {ip}: {response.status_code} - {response.text}")
    except Exception as e:
        logger.exception(f"Erro ao buscar reputação do IP {ip}.")
    return None

def insert_to_blacklist(conn, ip, reputation, geo_data):
    """
    Insere um IP na blacklist local com dados de geolocalização.
    """
    query = """
    INSERT INTO bl_address_local (
        ip_address, abuse_confidence_score,
        country_code, city, latitude, longitude
    )
    VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (ip_address) DO NOTHING;
    """
    execute_query(conn, query, (
        ip, reputation['abuseConfidenceScore'],
        geo_data['country_code'], geo_data['city'],
        geo_data['latitude'], geo_data['longitude']
    ))
    logger.info(f"IP {ip} adicionado à blacklist com score {reputation['abuseConfidenceScore']}.")

def insert_to_tarpit(conn, ip, geo_data):
    """
    Insere um IP na tabela TARPIT com dados de geolocalização.
    """
    query = """
    INSERT INTO tp_address_local (
        ip_address, country_code, city, latitude, longitude
    )
    VALUES (%s, %s, %s, %s, %s) ON CONFLICT (ip_address) DO NOTHING;
    """
    execute_query(conn, query, (
        ip,
        geo_data['country_code'], geo_data['city'],
        geo_data['latitude'], geo_data['longitude']
    ))
    logger.info(f"IP {ip} adicionado à TARPIT para análise futura.")

# Função principal
def main():
    """
    Função principal do script.
    """
    if len(sys.argv) < 2:
        logger.error("Nenhum IP fornecido ao tarpit-in.")
        return

    ip_to_check = sys.argv[1]

    # Verifica se o IP é privado
    if is_private_ip(ip_to_check):
        logger.info(f"IP privado ignorado: {ip_to_check}")
        return

    # Conexão com o banco de dados
    conn = None
    try:
        conn = get_db_connection()

        # Busca a reputação do IP
        reputation = fetch_ip_reputation(ip_to_check)

        # Busca os dados de geolocalização
        geo_data = get_geo_info(ip_to_check)
        if not geo_data:
            geo_data = {"country_code": None, "city": None, "latitude": None, "longitude": None}

        # Avalia a reputação e insere na blacklist ou tarpit
        if reputation and reputation.get('abuseConfidenceScore', 0) >= 75:
            insert_to_blacklist(conn, ip_to_check, reputation, geo_data)
        else:
            insert_to_tarpit(conn, ip_to_check, geo_data)
    except Exception as e:
        logger.critical(f"Erro crítico no processamento do IP {ip_to_check}: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    main()
