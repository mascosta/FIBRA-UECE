import requests
import psycopg2
import re
import os
from datetime import datetime, timezone
from ipaddress import ip_address
from logger import get_logger
import logging
from time import time

# Configurar o logger
logger = get_logger("tarpit-in", severity=logging.INFO)

logger.info("Iniciando checagem de reputação de IPs.")

# Dados de conexão ao banco de dados
db_host = 'localhost'
db_name = 'firewall'
db_user = 'admin'
db_password = 'Q1w2e3r4'

# Chave da API do AbuseIPDB
API_KEY = os.getenv('API_KEY')

def e_ip_privado(ip):
    return ip_address(ip).is_private

def obter_ips_para_checar():
    start_time = time()
    try:
        conexao = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
        cursor = conexao.cursor()
        cursor.execute("SELECT DISTINCT src_ip, src_country_code, src_city, src_longitude, src_latitude FROM network_traffic;")
        resultados = cursor.fetchall()
        logger.info(f"IPs obtidos para checagem: {len(resultados)}")
        return [(res[0], res[1], res[2], res[3], res[4]) for res in resultados if not e_ip_privado(res[0])]
    except Exception:
        logger.exception("Erro ao obter IPs para checagem.")
        return []
    finally:
        cursor.close()
        conexao.close()
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"IPs para checagem obtidos em {elapsed_time:.2f} ms.")

def ip_ja_existe_na_tp(ip_address):
    start_time = time()
    try:
        conexao = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
        cursor = conexao.cursor()
        cursor.execute("SELECT 1 FROM tp_address_local WHERE ip_address = %s;", (ip_address,))
        return cursor.fetchone() is not None
    except Exception:
        logger.exception("Erro ao verificar existência na tabela tp_address_local.")
        return False
    finally:
        cursor.close()
        conexao.close()
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Checagem de existência na tabela tp_address_local em {elapsed_time:.2f} ms.")

def inserir_na_bl_address_local(ip_address, country_code, city, src_longitude, src_latitude):
    start_time = time()
    try:
        conexao = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
        cursor = conexao.cursor()
        comando_sql = """
        INSERT INTO bl_address_local (ip_address, country_code, city, src_longitude, src_latitude)
        VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(comando_sql, (ip_address, country_code, city, src_longitude, src_latitude))
        conexao.commit()
        logger.info(f"IP {ip_address} inserido na tabela bl_address_local.")
    except Exception:
        logger.exception("Erro ao inserir IP na tabela bl_address_local.")
    finally:
        cursor.close()
        conexao.close()
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Inserção na tabela bl_address_local concluída em {elapsed_time:.2f} ms.")

def ip_existe_na_bl_address_local(ip_address):
    start_time = time()
    try:
        conexao = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
        cursor = conexao.cursor()
        cursor.execute("SELECT 1 FROM bl_address_local WHERE ip_address = %s;", (ip_address,))
        existe = cursor.fetchone() is not None
        logger.info(f"Checagem de existência na tabela bl_address_local para IP {ip_address}: {'Sim' if existe else 'Não'}.")
        return existe
    except Exception:
        logger.exception(f"Erro ao verificar na tabela bl_address_local para o IP {ip_address}.")
        return False
    finally:
        cursor.close()
        conexao.close()
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Checagem na tabela bl_address_local concluída em {elapsed_time:.2f} ms.")

def ip_existe_na_bl_local_cache(ip_address):
    start_time = time()
    try:
        conexao = psycopg2.connect(dbname=db_name, user=db_user, password=db_password, host=db_host)
        cursor = conexao.cursor()
        cursor.execute("SELECT 1 FROM bl_local_cache WHERE ip_address = %s;", (ip_address,))
        existe = cursor.fetchone() is not None
        logger.info(f"Checagem de existência no cache para IP {ip_address}: {'Sim' if existe else 'Não'}.")
        return existe
    except Exception:
        logger.exception(f"Erro ao verificar cache local para o IP {ip_address}.")
        return False
    finally:
        cursor.close()
        conexao.close()
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Checagem de cache concluída em {elapsed_time:.2f} ms.")

def checar_reputacao_ip_e_inserir(ip_address, src_longitude, src_latitude):
    start_time = time()
    try:
        if ip_ja_existe_na_tp(ip_address):
            logger.info(f"IP {ip_address} já existe na tabela tp_address_local. Ignorando.")
            return
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {'Key': API_KEY, 'Accept': 'application/json'}
        params = {'ipAddress': ip_address, 'maxAgeInDays': 15, 'verbose': ''}
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            dados = response.json()['data']
            inserir_dados_no_postgresql(dados, src_longitude, src_latitude)
        else:
            logger.error(f"Erro ao checar reputação do IP {ip_address}. Código: {response.status_code}")
    except Exception:
        logger.exception(f"Erro ao verificar reputação do IP {ip_address}.")
    finally:
        elapsed_time = (time() - start_time) * 1000
        logger.info(f"Checagem e inserção de reputação para o IP {ip_address} concluída em {elapsed_time:.2f} ms.")

def main():
    start_time = time()
    ips_para_checar = obter_ips_para_checar()
    for ip, country_code, city, longitude, latitude in ips_para_checar:
        if ip_existe_na_bl_local_cache(ip):
            if not ip_existe_na_bl_address_local(ip):
                inserir_na_bl_address_local(ip, country_code, city, longitude, latitude)
            else:
                logger.info(f"IP {ip} já existe na tabela bl_address_local. Ignorando.")
        else:
            checar_reputacao_ip_e_inserir(ip, longitude, latitude)
    elapsed_time = (time() - start_time) * 1000
    logger.info(f"Processamento completo de todos os IPs em {elapsed_time:.2f} ms.")

if __name__ == "__main__":
    main()
