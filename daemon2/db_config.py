# db_config.py

db_config = {
    'dbname': 'firewall',
    'user': 'admin',
    'password': 'Q1w2e3r4',
    'host': 'localhost'
}

def get_db_connection():
    """
    Cria uma conexão com o banco de dados usando psycopg2.
    """
    import psycopg2
    try:
        conn = psycopg2.connect(**db_config)
        return conn
    except Exception as e:
        raise Exception(f"Erro ao conectar ao banco de dados: {e}")
