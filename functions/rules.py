import subprocess
import psycopg2
import logging
from logger import get_logger
from time import time

# Configuração do logger
logger = get_logger("rules", severity=logging.INFO)
logger.info("Iniciando configuração de regras do firewall.")

# Configuração do PostgreSQL
db_config = {
    'dbname': 'firewall',
    'user': 'admin',
    'password': 'Q1w2e3r4',
    'host': 'localhost'
}

# Funções auxiliares
def execute_query(query, params=()):
    try:
        with psycopg2.connect(**db_config) as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchall() if query.strip().lower().startswith("select") else None
    except Exception as e:
        logger.exception(f"Erro ao executar query: {query}")
        return []

def run_iptables_command(command):
    try:
        subprocess.run(command, check=True, shell=True, stderr=subprocess.PIPE)
        logger.info(f"Comando executado com sucesso: {command}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao executar o comando {command}: {e.stderr.decode()}")

def setup_chains():
    for chain_name in ["TARPIT", "BLACKLIST", "WHITELIST"]:
        run_iptables_command(f"sudo iptables -N {chain_name} || sudo iptables -F {chain_name}")
    run_iptables_command(f"sudo iptables -A TARPIT -m limit --limit 60/min -j ACCEPT")
    run_iptables_command(f"sudo iptables -A TARPIT -j DROP")
    run_iptables_command(f"sudo iptables -A BLACKLIST -p tcp -j REJECT --reject-with tcp-reset")
    run_iptables_command(f"sudo iptables -A BLACKLIST -j DROP")
    run_iptables_command(f"sudo iptables -A WHITELIST -j ACCEPT")
    logger.info("Chains TARPIT, BLACKLIST e WHITELIST configuradas.")

def apply_whitelist_rules():
    whitelist_ips = execute_query("SELECT ip_address FROM wl_address_local")
    for ip, in whitelist_ips:
        for chain in ["FORWARD", "INPUT"]:
            run_iptables_command(f"sudo iptables -I {chain} -s {ip} -j WHITELIST")
    logger.info("Regras de WHITELIST aplicadas com sucesso.")

def main():
    start_time = time()
    try:
        setup_chains()
        apply_whitelist_rules()
    except Exception as e:
        logger.exception(f"Erro inesperado: {e}")
    finally:
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Execução do script rules concluída em {elapsed_time:.2f} ms.")

if __name__ == "__main__":
    main()
