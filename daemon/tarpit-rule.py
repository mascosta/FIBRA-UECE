import subprocess
import psycopg2
import sys
import logging
from logger import get_logger
from time import time

# Configuração do logger
logger = get_logger("tarpit-rule", severity=logging.INFO)
logger.info("Iniciando configuração de chains TARPIT e BLACKLIST.")

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

def apply_tarpit_rule(ip):
    for chain in ["FORWARD", "INPUT"]:
        run_iptables_command(f"sudo iptables -I {chain} -s {ip} -j TARPIT")
    logger.info(f"Regras de TARPIT aplicadas para o IP {ip}.")

def apply_blacklist_rule(ip):
    for chain in ["FORWARD", "INPUT"]:
        run_iptables_command(f"sudo iptables -I {chain} -s {ip} -j BLACKLIST")
    logger.info(f"Regras de BLACKLIST aplicadas para o IP {ip}.")

def setup_chains():
    for chain_name in ["TARPIT", "BLACKLIST"]:
        run_iptables_command(f"sudo iptables -N {chain_name} || sudo iptables -F {chain_name}")
    run_iptables_command(f"sudo iptables -A TARPIT -m limit --limit 60/min -j ACCEPT")
    run_iptables_command(f"sudo iptables -A TARPIT -j DROP")
    run_iptables_command(f"sudo iptables -A BLACKLIST -p tcp -j REJECT --reject-with tcp-reset")
    run_iptables_command(f"sudo iptables -A BLACKLIST -j DROP")
    logger.info("Chains TARPIT e BLACKLIST configuradas.")

def main():
    if len(sys.argv) < 2:
        logger.error("Nenhum IP fornecido ao tarpit-rule.")
        return

    ip_to_process = sys.argv[1]

    setup_chains()

    # Determina se o IP deve ser tratado como TARPIT ou BLACKLIST
    if execute_query("SELECT 1 FROM tp_address_local WHERE ip_address = %s", (ip_to_process,)):
        apply_tarpit_rule(ip_to_process)
    elif execute_query("SELECT 1 FROM bl_address_local WHERE ip_address = %s", (ip_to_process,)):
        apply_blacklist_rule(ip_to_process)
    else:
        logger.warning(f"IP {ip_to_process} não encontrado em TARPIT ou BLACKLIST.")

if __name__ == "__main__":
    main()
