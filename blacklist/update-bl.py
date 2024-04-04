import requests
import psycopg2
from datetime import datetime

# Dados de conexão ao banco de dados PostgreSQL
db_host = 'localhost'
db_name = 'firewall'
db_user = 'admin'
db_password = 'Q1w2e3r4'

# Sua chave de API do AbuseIPDB
API_KEY = '${API_KEY}'

def buscar_dados():
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'confidenceMinimum': 75,
        'limit': 9999999
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Erro ao buscar dados: {response.status_code}")
        return None

def inserir_dados_no_postgresql(dados):
    conexao = psycopg2.connect(
        dbname=db_name,
        user=db_user,
        password=db_password,
        host=db_host
    )
    cursor = conexao.cursor()
    
    for registro in dados['data']:
        # Formata a data para o padrão aceito pelo PostgreSQL
        data_formatada = datetime.strptime(registro['lastReportedAt'], "%Y-%m-%dT%H:%M:%S+00:00")
        
        comando_sql = """
        INSERT INTO bl_local_cache (ip_address, country_code, abuse_confidence_score, last_reported_at)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(comando_sql, (registro['ipAddress'], registro['countryCode'], registro['abuseConfidenceScore'], data_formatada))
    
    conexao.commit()
    cursor.close()
    conexao.close()

dados = buscar_dados()
if dados:
    inserir_dados_no_postgresql(dados)
