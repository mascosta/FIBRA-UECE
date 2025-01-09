import logging
import os

# Diretório de logs
log_dir = "/var/log/firewall/"
os.makedirs(log_dir, exist_ok=True)

def get_logger(script_name, severity=logging.INFO):
    """
    Configura um logger individual para cada script e severidade específica.
    
    :param script_name: Nome do script que será usado no arquivo de log.
    :param severity: Nível de severidade do log (DEBUG, INFO, WARNING, etc.).
    :return: Logger configurado.
    """
    logger = logging.getLogger(script_name)
    
    # Evitar múltiplos handlers
    if not logger.hasHandlers():
        try:
            logger.setLevel(severity)
            
            # Formato do log
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            
            # Handler para arquivo de log específico do script
            file_handler = logging.FileHandler(os.path.join(log_dir, f'{script_name}.log'))
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            
            # Opcional: log no console
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        except Exception as e:
            print(f"Erro ao configurar o logger para {script_name}: {e}")
    
    return logger
