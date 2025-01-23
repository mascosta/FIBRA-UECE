import requests
import psycopg2
import os
import logging
from ipaddress import ip_address
from logger import get_logger
import sys
from time import time

# Configuração do logger
logger = get_logger("tarpit-in", severity=logging.INFO)
logger.info("Iniciando checagem de reputação de IPs.")

# Configuração do PostgreSQL
db_config = {
    'dbname': 'firewall',
    'user': 'admin',
    'password': 'Q1w2e3r4',
    'host': 'localhost'
}

# Chave da API do AbuseIPDB
API_KEY = os.getenv('API_KEY')

# Funções auxiliares
def is_private_ip(ip):
    return ip_address(ip).is_private

def execute_query(query, params=()):
    try:
        with psycopg2.connect(**db_config) as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                if query.strip().lower().startswith("select"):
                    return cur.fetchall()
                conn.commit()
    except Exception as e:
        logger.exception(f"Erro ao executar query: {query}")
        return []

def fetch_ip_reputation(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Key': API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 15}
    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            return response.json()['data']
        else:
            logger.error(f"Erro na API AbuseIPDB para {ip}: {response.status_code}")
    except Exception as e:
        logger.exception(f"Erro ao buscar reputação do IP {ip}.")
    return None

def insert_to_blacklist(ip, reputation):
    query = """
    INSERT INTO bl_address_local (ip_address, abuse_confidence_score)
    VALUES (%s, %s) ON CONFLICT (ip_address) DO NOTHING;
    """
    execute_query(query, (ip, reputation['abuseConfidenceScore']))
    logger.info(f"IP {ip} adicionado à blacklist com score {reputation['abuseConfidenceScore']}.")

def insert_to_tarpit(ip, country_code=None, abuse_confidence_score=None, last_reported_at=None):
    """
    Insere um IP na tabela tp_address_local, permitindo valores nulos para colunas opcionais.
    """
    query = """
    INSERT INTO tp_address_local (ip_address, country_code, abuse_confidence_score, last_reported_at)
    VALUES (%s, %s, %s, %s)
    ON CONFLICT (ip_address) DO NOTHING;
    """
    try:
        execute_query(query, (ip, country_code, abuse_confidence_score, last_reported_at))
        logger.info(f"IP {ip} adicionado à tarpit com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao inserir IP {ip} na tarpit: {e}")

def handle_unknown_ip(ip, reputation_data):
    """
    Processa um IP público desconhecido e tenta inseri-lo na tarpit.
    """
    country_code = reputation_data.get('countryCode') if reputation_data else None
    abuse_confidence_score = reputation_data.get('abuseConfidenceScore') if reputation_data else None
    last_reported_at = reputation_data.get('lastReportedAt') if reputation_data else None

    # Insere o IP na tarpit mesmo que algumas informações estejam ausentes
    insert_to_tarpit(ip, country_code, abuse_confidence_score, last_reported_at)


# Função principal
def main():
    if len(sys.argv) < 2:
        logger.error("Nenhum IP fornecido ao tarpit-in.")
        return

    ip_to_check = sys.argv[1]

    if is_private_ip(ip_to_check):
        logger.info(f"IP privado ignorado: {ip_to_check}")
        return

    reputation = fetch_ip_reputation(ip_to_check)

    if reputation and reputation['abuseConfidenceScore'] >= 75:
        insert_to_blacklist(ip_to_check, reputation)
    else:
        insert_to_tarpit(ip_to_check)

if __name__ == "__main__":
    main()
