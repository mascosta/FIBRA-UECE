import subprocess
import sys
import logging
import os
from pathlib import Path
from logger import get_logger

# Configuração do logger
logger = get_logger("manager", severity=logging.INFO)

# Caminhos padrão configuráveis via variáveis de ambiente
fibra_path = Path(os.getenv("FIBRA_PATH", "/opt/fibra"))
python_path = Path(os.getenv("PYTHON_PATH", "/usr/bin/python3"))

def call_script(script_name, *args):
    """
    Chama um script auxiliar e passa argumentos.
    
    :param script_name: Caminho completo do script a ser executado.
    :param args: Argumentos adicionais para o script.
    """
    try:
        command = [str(python_path), str(script_name), *args]
        logger.info(f"Executando comando: {' '.join(command)}")
        subprocess.run(command, check=True)
        logger.info(f"Script {script_name} executado com sucesso com args {args}.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao executar o script {script_name}: {e}")
    except FileNotFoundError:
        logger.error(f"Script {script_name} não encontrado. Verifique o caminho.")
    except Exception as e:
        logger.exception(f"Erro inesperado ao tentar executar {script_name}: {e}")

def main():
    """
    Gerencia a execução dos scripts auxiliares para processar endereços IP.
    """
    if len(sys.argv) < 2:
        logger.error("Nenhum IP fornecido ao Manager.")
        return

    ip_to_process = sys.argv[1]
    logger.info(f"IP recebido para processamento: {ip_to_process}")

    try:
        # Chama o tarpit-in.py para verificar reputação
        call_script(fibra_path / "tarpit-in.py", ip_to_process)

        # Chama o rules_manager.py para gerenciar todas as regras (TARPIT, BLACKLIST, WHITELIST)
        call_script(fibra_path / "rules_manager.py", ip_to_process)
    except Exception as e:
        logger.exception(f"Erro geral no processamento do IP {ip_to_process}: {e}")

if __name__ == "__main__":
    main()
