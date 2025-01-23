import requests
import psycopg2
import os
import logging
from ipaddress import ip_address
from logger import get_logger
import sys

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

def execute_query(query, params=()):
    """
    Executa uma consulta no banco de dados PostgreSQL.
    """
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

def insert_to_blacklist(ip, reputation):
    """
    Insere um IP na blacklist local.
    """
    query = """
    INSERT INTO bl_address_local (ip_address, abuse_confidence_score)
    VALUES (%s, %s) ON CONFLICT (ip_address) DO NOTHING;
    """
    execute_query(query, (ip, reputation['abuseConfidenceScore']))
    logger.info(f"IP {ip} adicionado à blacklist com score {reputation['abuseConfidenceScore']}.")

def insert_to_tarpit(ip):
    """
    Insere um IP na tabela TARPIT para degradação futura.
    """
    query = """
    INSERT INTO tp_address_local (ip_address)
    VALUES (%s) ON CONFLICT (ip_address) DO NOTHING;
    """
    execute_query(query, (ip,))
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

    # Busca a reputação do IP
    reputation = fetch_ip_reputation(ip_to_check)

    # Avalia a reputação e insere na blacklist ou tarpit
    if reputation and reputation.get('abuseConfidenceScore', 0) >= 75:
        insert_to_blacklist(ip_to_check, reputation)
    else:
        insert_to_tarpit(ip_to_check)

if __name__ == "__main__":
    main()
