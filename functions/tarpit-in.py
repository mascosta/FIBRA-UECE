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

def insert_to_tarpit(ip):
    query = """
    INSERT INTO tp_address_local (ip_address)
    VALUES (%s) ON CONFLICT (ip_address) DO NOTHING;
    """
    execute_query(query, (ip,))
    logger.info(f"IP {ip} adicionado à TARPIT para análise futura.")

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
