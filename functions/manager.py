import subprocess
import sys
import logging
from pathlib import Path
from logger import get_logger

logger = get_logger("manager", severity=logging.INFO)

fibraPath = Path("/vm_share/FIBRA-UECE/functions")
pythonPath = Path("/opt/FIBRA-UECE/python/bin/python3")

def call_script(script_name, *args):
    """Chama um script auxiliar e passa argumentos."""
    try:
        command = [pythonPath, script_name, *args]
        subprocess.run(command, check=True)
        logger.info(f"Script {script_name} executado com sucesso com args {args}.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Erro ao executar o script {script_name}: {e}")

def main():
    if len(sys.argv) < 2:
        logger.error("Nenhum IP fornecido ao Manager.")
        return

    ip_to_process = sys.argv[1]

    # Chama o tarpit-in.py para verificar reputação
    call_script(fibraPath / "tarpit-in.py", ip_to_process)

    # Chama o tarpit-rule.py para gerenciar regras TARPIT
    call_script(fibraPath / "tarpit-rule.py", ip_to_process)

    # Chama o rules.py para gerenciar BLACKLIST e WHITELIST
    call_script(fibraPath / "rules.py")

if __name__ == "__main__":
    main()
