import subprocess
import sys
import time
import os
import logging
from pathlib import Path
from db_config import get_db_connection
from geo_helper import get_geo_info
from logger import get_logger, log_execution_time
from tarpit_in import fetch_ip_reputation, insert_to_blacklist, insert_or_update_tarpit, remove_from_tarpit

# Configuração do logger
logger = get_logger("manager", severity=logging.INFO)

# Caminhos configuráveis
fibra_path = Path(os.getenv("FIBRA_PATH", "/etc/fibra"))

def handle_ip_lists(conn, ip):
    """
    Verifica se o IP está na whitelist ou blacklist.
    Se estiver, remove-o da TARPIT.
    """
    try:
        for table in ["wl_address_local", "bl_address_local"]:
            query = f"SELECT 1 FROM {table} WHERE ip_address = %s;"
            with conn.cursor() as cursor:
                cursor.execute(query, (ip,))
                if cursor.fetchone():
                    logger.info(f"IP {ip} encontrado na tabela {table}.")
                    remove_from_tarpit(conn, ip)  # Remove da TARPIT se já estiver processado
                    return table  # Retorna a tabela onde o IP foi encontrado
        return None
    except Exception as e:
        logger.error(f"Erro ao verificar listas para IP {ip}: {e}")
        return None

def log_network_traffic(conn, src_ip, dst_ip, protocol_name="TCP", src_service=None, dst_service=None,
                        src_country_code=None, src_city=None, src_latitude=None, src_longitude=None,
                        dst_country_code=None, dst_city=None, dst_latitude=None, dst_longitude=None,
                        src_port=None, dst_port=None):
    """
    Registra informações de tráfego de rede na tabela network_traffic.
    """
    query = """
    INSERT INTO network_traffic (
        timestamp, src_ip, dst_ip, protocol_name, src_service, dst_service,
        src_country_code, src_city, src_latitude, src_longitude,
        dst_country_code, dst_city, dst_latitude, dst_longitude,
        src_port, dst_port
    )
    VALUES (
        NOW(), %s, %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s
    );
    """
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, (
                src_ip, dst_ip, protocol_name, src_service, dst_service,
                src_country_code, src_city, src_latitude, src_longitude,
                dst_country_code, dst_city, dst_latitude, dst_longitude,
                src_port, dst_port
            ))
            conn.commit()
            logger.info(f"Registro de tráfego: {src_ip} -> {dst_ip} armazenado com sucesso.")
    except Exception as e:
        logger.error(f"Erro ao registrar tráfego de rede: {e}")

def execute_rule_manager(ip=None):
    """
    Chama o script rule_manager.py para aplicar as regras de firewall.
    Se um IP for fornecido, apenas processa as regras para aquele IP.
    Caso contrário, aplica as regras gerais.
    """
    try:
        logger.info("Executando subprocesso para 'rule_manager.py'")

        # Monta o comando para o subprocesso
        command = [sys.executable, str(fibra_path / "rule_manager.py")]
        if ip:
            command.append(ip)  # Adiciona o IP como argumento, se fornecido

        # Medir o tempo de execução do subprocesso
        start_time = time.time()
        result = subprocess.run(command, capture_output=True, text=True)
        elapsed_time = time.time() - start_time

        logger.info(f"Tempo total gasto no subprocesso 'rule_manager.py': {elapsed_time:.2f} segundos.")

        # Captura e exibe a saída do subprocesso no log
        if result.returncode != 0:
            logger.error(f"Erro no subprocesso 'rule_manager.py': {result.stderr.strip()}")
        else:
            logger.info(f"Subprocesso 'rule_manager.py' executado com sucesso.")
            logger.info(f"Saída do subprocesso: {result.stdout.strip()}")

    except Exception as e:
        logger.critical(f"Erro ao executar subprocesso 'rule_manager.py': {e}")

def execute_tarpit_in(ip):
    """
    Chama o script tarpit_in.py como subprocesso e registra tempo de execução.
    """
    try:
        logger.info(f"Executando subprocesso para 'tarpit_in.py' com IP {ip}")
        start_time = time.time()

        result = subprocess.run(
            [sys.executable, str(fibra_path / "tarpit_in.py"), ip],
            capture_output=True,
            text=True
        )

        elapsed_time = time.time() - start_time
        logger.info(f"Tempo total gasto no subprocesso 'tarpit_in.py' para o IP {ip}: {elapsed_time:.2f} segundos.")

        if result.returncode != 0:
            logger.error(f"Erro no subprocesso 'tarpit_in.py' para o IP {ip}: {result.stderr.strip()}")
        else:
            logger.info(f"Subprocesso 'tarpit_in.py' executado com sucesso para o IP {ip}.")
            logger.info(f"Saída do subprocesso: {result.stdout.strip()}")

    except Exception as e:
        logger.critical(f"Erro ao executar subprocesso 'tarpit_in.py' para o IP {ip}: {e}")

def process_ip(ip):
    """
    Processa o endereço IP recebido, verificando listas e classificando.
    """
    conn = None
    try:
        conn = get_db_connection()

        # Verifica se o IP está na whitelist ou blacklist
        found_in_table = handle_ip_lists(conn, ip)
        if found_in_table:
            logger.info(f"IP {ip} já processado (encontrado na {found_in_table}). Nenhuma ação adicional necessária.")
            return

        # Log de início de análise
        logger.info(f"Iniciando checagem de reputação para o IP: {ip}")

        # Busca reputação do IP
        reputation = fetch_ip_reputation(ip)
        if not reputation:
            logger.warning(f"Reputação do IP {ip} não encontrada. Ignorando.")
            return

        # Busca os dados de geolocalização
        geo_data = get_geo_info(ip, logger=logger)
        if not geo_data:
            geo_data = {"country_code": None, "city": None, "latitude": None, "longitude": None}

        # Registra o tráfego de rede na tabela
        log_network_traffic(
            conn, 
            src_ip=ip, 
            dst_ip="192.168.0.1",  # Exemplo: substitua por um valor real
            protocol_name="TCP",  # Ajuste conforme necessário
            src_country_code=geo_data.get("country_code"),
            src_city=geo_data.get("city"),
            src_latitude=geo_data.get("latitude"),
            src_longitude=geo_data.get("longitude"),
            src_port=12345,  # Ajuste conforme necessário
            dst_port=80  # Ajuste conforme necessário
        )

        # Classifica o IP com base na reputação
        if reputation.get('abuseConfidenceScore', 0) >= 75:
            insert_to_blacklist(conn, ip, reputation, geo_data)
        else:
            insert_or_update_tarpit(conn, ip, reputation, geo_data)

        # Executa o tarpit_in.py como subprocesso para registro detalhado
        execute_tarpit_in(ip)
        execute_rule_manager(ip)

    except Exception as e:
        logger.critical(f"Erro crítico no processamento do IP {ip}: {e}")
    finally:
        if conn:
            conn.close()

@log_execution_time(logger)
def main():
    """
    Gerencia a execução do processamento de IPs.
    """
    if len(sys.argv) < 2:
        logger.error("Nenhum IP fornecido ao Manager.")
        return

    ip_to_process = sys.argv[1]
    logger.info(f"Iniciando processamento para o IP: {ip_to_process}")
    process_ip(ip_to_process)

if __name__ == "__main__":
    main()
