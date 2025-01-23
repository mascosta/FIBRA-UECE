import logging
import subprocess
from time import time
from db_config import get_db_connection
from geo_helper import get_geo_info
from logger import get_logger

# Configuração do logger
logger = get_logger("rules_manager", severity=logging.INFO)
logger.info("Iniciando o script rules_manager.")

# Função para medir o tempo de execução
def log_execution_time(func):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = func(*args, **kwargs)
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Função '{func.__name__}' concluída em {elapsed_time:.2f} ms.")
        return result
    return wrapper

# Funções auxiliares
@log_execution_time
def run_iptables_command(command):
    try:
        subprocess.run(command, check=True, shell=True, stderr=subprocess.PIPE)
        logger.info(f"Comando executado com sucesso: {command}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao executar o comando {command}: {e.stderr.decode()}")

@log_execution_time
def execute_query(query, params=()):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                return cur.fetchall() if query.strip().lower().startswith("select") else None
    except Exception as e:
        logger.exception(f"Erro ao executar query: {query}")
        return []

@log_execution_time
def setup_chains():
    for chain_name in ["TARPIT", "BLACKLIST", "WHITELIST"]:
        run_iptables_command(f"sudo iptables -N {chain_name} || sudo iptables -F {chain_name}")
    run_iptables_command(f"sudo iptables -A TARPIT -m limit --limit 60/min -j ACCEPT")
    run_iptables_command(f"sudo iptables -A TARPIT -j DROP")
    run_iptables_command(f"sudo iptables -A BLACKLIST -p tcp -j REJECT --reject-with tcp-reset")
    run_iptables_command(f"sudo iptables -A BLACKLIST -j DROP")
    run_iptables_command(f"sudo iptables -A WHITELIST -j ACCEPT")
    logger.info("Chains TARPIT, BLACKLIST e WHITELIST configuradas.")

@log_execution_time
def apply_tarpit_rule(ip):
    for chain in ["FORWARD", "INPUT"]:
        run_iptables_command(f"sudo iptables -I {chain} -s {ip} -j TARPIT")
    logger.info(f"Regras de TARPIT aplicadas para o IP {ip}.")

@log_execution_time
def apply_blacklist_rule(ip):
    for chain in ["FORWARD", "INPUT"]:
        run_iptables_command(f"sudo iptables -I {chain} -s {ip} -j BLACKLIST")
    logger.info(f"Regras de BLACKLIST aplicadas para o IP {ip}.")

@log_execution_time
def apply_whitelist_rules():
    whitelist_ips = execute_query("SELECT ip_address FROM wl_address_local")
    for ip, in whitelist_ips:
        for chain in ["FORWARD", "INPUT"]:
            run_iptables_command(f"sudo iptables -I {chain} -s {ip} -j WHITELIST")
    logger.info("Regras de WHITELIST aplicadas com sucesso.")

@log_execution_time
def process_ip(ip_to_process):
    # Determina se o IP deve ser tratado como TARPIT ou BLACKLIST
    if execute_query("SELECT 1 FROM tp_address_local WHERE ip_address = %s", (ip_to_process,)):
        apply_tarpit_rule(ip_to_process)
    elif execute_query("SELECT 1 FROM bl_address_local WHERE ip_address = %s", (ip_to_process,)):
        apply_blacklist_rule(ip_to_process)
    else:
        logger.warning(f"IP {ip_to_process} não encontrado em TARPIT ou BLACKLIST.")

# Função principal
@log_execution_time
def main(ip_to_process=None):
    setup_chains()
    apply_whitelist_rules()

    if ip_to_process:
        process_ip(ip_to_process)

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        ip = sys.argv[1]
        logger.info(f"Processando IP: {ip}")
        main(ip_to_process=ip)
    else:
        logger.info("Nenhum IP fornecido. Aplicando apenas regras gerais.")
        main()
