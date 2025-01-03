import subprocess
import psycopg2
from logger import get_logger
import logging
from time import time

# Configurar o logger
logger = get_logger("rules", severity=logging.INFO)

logger.info("Iniciando configuração de regras do firewall.")

# Configurações do PostgreSQL
db_host = 'localhost'
db_name = 'firewall'
db_user = 'admin'
db_password = 'Q1w2e3r4'

def run_iptables_command(command):
    start_time = time()
    try:
        subprocess.run(command, check=True, shell=True, capture_output=True)
        logger.info(f"Comando executado com sucesso: {command}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao executar o comando: {command}. Erro: {e.stderr.decode()}")
    finally:
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Execução do comando '{command}' concluída em {elapsed_time:.2f} ms.")

def create_or_flush_chain(chain_name):
    start_time = time()
    try:
        subprocess.run(f'sudo iptables -N {chain_name} 2>/dev/null || sudo iptables -F {chain_name}', shell=True)
        logger.info(f"Chain {chain_name} criada ou limpa.")
    except Exception as e:
        logger.error(f"Erro ao criar ou limpar a chain {chain_name}: {e}")
    finally:
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Chain {chain_name} processada em {elapsed_time:.2f} ms.")

def setup_tarpit_and_blacklist_chains():
    start_time = time()
    try:
        # Configurações específicas para as chains TARPIT e BLACKLIST
        run_iptables_command(f'sudo iptables -A TARPIT -m limit --limit 60/min -j ACCEPT')
        run_iptables_command(f'sudo iptables -A TARPIT -j DROP')
        logger.info("Regras de limitação de taxa configuradas na chain TARPIT.")

        run_iptables_command(f'sudo iptables -A BLACKLIST -p tcp -j REJECT --reject-with tcp-reset')
        run_iptables_command(f'sudo iptables -A BLACKLIST -j DROP')
        logger.info("Chain BLACKLIST configurada com regra de REJECT.")
    except Exception as e:
        logger.error(f"Erro ao configurar as chains TARPIT e BLACKLIST: {e}")
    finally:
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Configuração das chains TARPIT e BLACKLIST concluída em {elapsed_time:.2f} ms.")

def setup_whitelist_chain():
    start_time = time()
    try:
        # Aceitar todo o tráfego que chega na chain WHITELIST
        run_iptables_command(f'sudo iptables -A WHITELIST -j ACCEPT')
        logger.info("Chain WHITELIST configurada para aceitar todo o tráfego.")
    except Exception as e:
        logger.error(f"Erro ao configurar a chain WHITELIST: {e}")
    finally:
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Configuração da chain WHITELIST concluída em {elapsed_time:.2f} ms.")

def apply_whitelist_rules():
    start_time = time()
    try:
        conn = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
        cur = conn.cursor()

        # Processar endereços WP
        cur.execute("SELECT ip_address FROM wl_address_local")
        ips = cur.fetchall()
        for ip in ips:
            for chain in ["FORWARD", "INPUT"]:
                run_iptables_command(f'sudo iptables -I {chain} -s {ip[0]} -j WHITELIST')
                logger.info(f"Regras de WHITELIST aplicadas para o IP {ip[0]} em {chain}.")

        cur.close()
        conn.close()
    except psycopg2.DatabaseError:
        logger.exception("Erro de banco de dados ao aplicar regras de WHITELIST.")
    except Exception:
        logger.exception("Erro inesperado ao aplicar regras de WHITELIST.")
    finally:
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Aplicação de regras de WHITELIST concluída em {elapsed_time:.2f} ms.")

def main():
    start_time = time()
    try:
        # Criar ou limpar as chains necessárias
        for chain_name in ["TARPIT", "BLACKLIST", "WHITELIST"]:
            create_or_flush_chain(chain_name)

        setup_tarpit_and_blacklist_chains()  # Configuração inicial para TARPIT e BLACKLIST
        setup_whitelist_chain()  # Configura a nova chain WHITELIST
        apply_whitelist_rules()  # Aplica as novas regras para WHITELIST
    except Exception:
        logger.exception("Erro inesperado na execução principal.")
    finally:
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Execução do script principal concluída em {elapsed_time:.2f} ms.")

if __name__ == "__main__":
    main()
