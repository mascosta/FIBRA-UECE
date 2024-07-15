
# Dissertacao FIBRA-UECE :closed_book:

**Repositório dos códigos para dissertação do tema de Firewall automatizado.**

O objetivo dessa ferramenta é aumentar o nível de segurança de um firewall de borda evitando a negação inicial do serviço, enquanto é efetuada a análise do tráfego registrado.

## Pacotes e bibliotecas necessários(as) antes da execução. :penguin: 

Obs.: Visando facilitar a replicação deste guia, será considerado que o diretório vigente é o /opt.

### Preparação do ambiente:


```bash

# Navegando para o diretório especificado.

cd /opt

# Atualizando o sistema

apt update -y && \

# Instalando pacotes

apt install vim wget bash-completion \
 tcpdump net-tools curl telnet \
 nmap zip git unzip python3-pip python3-venv -y && \

wget https://github.com/maxmind/geoipupdate/releases/download/v6.1.0/geoipupdate_6.1.0_linux_amd64.deb && \

dpkg -i geoipupdate_6.1.0_linux_amd64.deb && \

# Instalação do Docker

curl -fsSL https://get.docker.com | bash && \

# Clonar o repositório

git clone https://github.com/mascosta/FIBRA-UECE-UECE.git

# Criar estrutura complementar ao repositório

mkdir -p /opt/FIBRA-UECE/docker/postgres/data && \

mkdir -p /opt/FIBRA-UECE/docker/grafana && \ 

mkdir -p /opt/FIBRA-UECE/python && \ 

chmod 777 -R /opt/FIBRA-UECE/ && \

python3 -m venv /opt/FIBRA-UECE/python/ && \

# Removendo cache de pacotes da instância

apt clean

```

### Baixando bibliotecas:


```bash

# Entrar no ambiente virtual (VENV)

source /opt/FIBRA-UECE/python/bin/activate

# Instalação das bibliotecas via PIP

pip install geoip2 scapy requests datetime psycopg2-binary

```

## Usando a ferramenta :snake:

Agora que os pacotes e bibliotecas estão devidamente instalados, é necessário o ajuste para execução das ferramentas. Onde uma executa em forma de daemon e outras em forma de rotinas, carregando e liberando dados de acordo com o agendamento (CRON).

### 1. Coletando a blacklist remota  :earth_americas:

Para o funcionamento básico do projeto, será adicionada uma entrada no ```/etc/crontab``` com o seguinte comando:

```bash

0 0,12 * * * root python3 /opt/FIBRA-UECE/blacklist/update-bl.py

```

Com essa execução, todo dia a meia noite e meio dia o script atualizará a base de dados local com os registros de blacklist.


### 2. Executando o script de "escuta" da interface :mag_right:

Após o download da lista atualizada é necessário iniciar o *sniff* da rede para concatenar os endereços que estão tentando acesso com o existentes na lista baixada.

Para essa tarefa, é necessário executar o comando abaixo:

```bash

/opt/FIBRA-UECE/python/bin/python3 /opt/FIBRA-UECE/collect/collect-pgsql-ipv4-tcp-syn.py > /dev/null &

```

Com essa execução, toda comunicação que chegar na interface que seja TCP, com endereço de IPv4 público será adicionado à tabela "network_traffic"

### 3. Criando a blacklist local :bookmark_tabs:

Considerando que já existe uma tabela onde os endereços com má reputação estão inseridos e uma outra onde registra em tempo real as conexões oriundas de IPs públicos, faz-se necessária a concatenação desses endereços para uma análise mais detalhada, caso o edereço não esteja diretamente nessa lista.

Essa execução será tabém executada através de rotina, adicionando a seguinte linha no arquivo /etc/crontab:

```bash

0/10 * * * * root /opt/FIBRA-UECE/python/bin/python3 /opt/FIBRA-UECE/tarpit/tarpit-in3.py > /dev/null &

```