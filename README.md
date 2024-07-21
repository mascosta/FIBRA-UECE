
# Dissertacao FIBRA-UECE :closed_book:

**Repositório dos códigos para dissertação do tema de Firewall automatizado.**

O objetivo dessa ferramenta é aumentar o nível de segurança de um firewall de borda evitando a negação inicial do serviço, enquanto é efetuada a análise do tráfego registrado.

**Dicas e considerações de "preflight"** 

Como a execução foi validada em um ambiente em nuvem pública, usando uma distribuição linux específica, é interessante algumas considerações e a tomada de alguns cuidados:

* A distribuição usada para replicação desse guia foi a Debian/Linux. Caso seja usada uma outra distribuição, alguns passos aqui devem ser ajustados.

* Nas regras de entrada, tentar limitar o endereço de origem para a conexão antes da solução ter sido devidamente configurada.

* Talvez o shape da máquina virtual não seja o suficiente, com 1 core de processador e 1GB de RAM. Caso isso aconteça, pode ser ajustada SWAP, para não limitar a execução e correr inclusive o risco de travar o servidor, por meio dos seguintes comandos:

```bash

fallocate -l 1G /opt/swapfile
sudo chmod 600 /opt/swapfile
mkswap /opt/swapfile
swapon /opt/swapfile
```

* Para não liberar portas de banco e acesso web diretamente, é interessante o uso de um túnel ssh, através de uma sintaxe similar:

```bash

#ssh -i chave_de_conexão.pem usuario_padrao@ip_publico -L porta_local:localhost_remoto:porta_remota, Ex.:

ssh -i chave.pem admin@44.203.88.120 -L 3000:127.0.0.1:3000
```

## Pacotes e bibliotecas necessários(as) antes da execução. :penguin: 

Obs.: Visando facilitar a replicação deste guia, será considerado que o diretório vigente é o /opt.

### Preparação do ambiente:


```bash

# Navegando para o diretório especificado.

cd /opt

# Atualizando o sistema

apt update -y && \

# Instalando o git

apt install git -y &&

# Clonar o repositório

git clone https://github.com/mascosta/FIBRA-UECE.git && \

# Instalando demais pacotes

apt install vim wget bash-completion \
 tcpdump net-tools curl telnet \
 nmap zip unzip python3-pip python3-venv -y && \

# Instalação do Docker

curl -fsSL https://get.docker.com | bash && \

# Criar estrutura complementar ao repositório

mkdir -p /opt/FIBRA-UECE/docker/postgres/data && \

mkdir -p /opt/FIBRA-UECE/docker/grafana && \ 

mkdir -p /opt/FIBRA-UECE/python && \ 

chmod 777 -R /opt/FIBRA-UECE/ && \

python3 -m venv /opt/FIBRA-UECE/python/ && \

# Removendo cache de pacotes da instância

apt clean
```

### Baixando e armazenando a base de Geolocalização

Alguns provedores oferecem, de forma gratuita, uma base de dados que relaciona **Endereços IP** com **Geolocalização**. 

Para a solução, foi adotada a base da *MaxMind*, através do processo descrito abaixo:


```bash

# Baixando e instalando o executável do geoipupdate

wget https://github.com/maxmind/geoipupdate/releases/download/v6.1.0/geoipupdate_6.1.0_linux_amd64.deb && \

# Realizando a instalação.

dpkg -i geoipupdate_6.1.0_linux_amd64.deb && \

# Editar o arquivo de configuração

vim /usr/share/doc/geoipupdate/GeoIP.conf
```

A *MaxMind* precisa que seja feito um cadastro para a disponibilização dessa base. Sendo assim, após o cadastro devidamente feito, serão gerados o ```AccountID``` e a ```LicenseKey```.

Sendo necessário apenas inserir essas informações no arquivo citado assim, como o exemplo abaixo:

```conf

# GeoIP.conf file for `geoipupdate` program, for versions >= 3.1.1.
# Used to update GeoIP databases from https://www.maxmind.com.
# For more information about this config file, visit the docs at
# https://dev.maxmind.com/geoip/updating-databases.

# `AccountID` is from your MaxMind account.
AccountID S3u1D4qu1

# Replace YOUR_LICENSE_KEY_HERE with an active license key associated
# with your MaxMind account.
LicenseKey Su4L1c3ns3K3y4qu1

# `EditionIDs` is from your MaxMind account.
EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country
```

Após a configuração, basta gerar o comando abaixo para coleta da base:

```bash

geoipupdate -f /usr/share/doc/geoipupdate/GeoIP.conf
```

### Baixando bibliotecas:


```bash

# Entrar no ambiente virtual (VENV)

source /opt/FIBRA-UECE/python/bin/activate

# Instalação das bibliotecas via PIP

pip install geoip2 scapy requests datetime psycopg2-binary
```

## Usando a ferramenta :snake:

Agora que os pacotes e bibliotecas estão devidamente instalados, é necessária a inicialização dos containers para armazenamento de dados , exbição e gerenciamento dos dados usando as soluções *Postgre*, *Grafana* e *pgAdmin*, respectivamente. Onde uma executa em forma de daemon e outras em forma de rotinas, carregando e liberando dados de acordo com o agendamento (CRON).

Algumas das ferramentas/scripts usam uma API, gerada na plataforma do *AbuseIPDB*. Sendo assim, ao invés de colocá-las diretamente no código, deve-se exportá-la como variável de ambiente e, na execução do script em python, usar a chamada ```os.getenv('API_KEY')```. Para atribuí-la como variável de ambiente, basta executar:

```bash

export API_KEY=SuaChaveAqui
```


### 1. Executando os containers  :whale:

A execução dos containers é feita via docker-compose. Por conta do stack de serviços citados. Para essa execução, basta executar o seguinte comando:

```bash

docker compose -f /opt/FIBRA-UECE/docker/docker-compose.yaml up -d
```

Com os containers em execução, faz-se necessário o ajuste para execução das ferramentas. Onde uma executa em forma de daemon e outras em forma de rotinas, carregando e liberando dados de acordo com o agendamento (CRON). 

### 2. Coletando a blacklist remota  :earth_americas:

Para o funcionamento básico do projeto, será adicionada uma entrada no ```/etc/crontab``` com o seguinte comando:

```bash

0 0,12 * * * python3 /opt/FIBRA-UECE/blacklist/update-bl.py
```

Com essa execução, todo dia a meia noite e meio dia o script atualizará a base de dados local com os registros de blacklist.


### 3. Executando o script de "escuta" da interface :mag_right:

Após o download da lista atualizada é necessário iniciar o *sniff* da rede para concatenar os endereços que estão tentando acesso com o existentes na lista baixada.

Para essa tarefa, é necessário executar o comando abaixo:

```bash

/opt/FIBRA-UECE/python/bin/python3 /opt/FIBRA-UECE/collect/collect-pgsql-ipv4-tcp-syn.py > /dev/null &
```

Com essa execução, toda comunicação que chegar na interface que seja TCP, com endereço de IPv4 público será adicionado à tabela "network_traffic"

### 4. Ajustando a crontab para execução periódica das regras :bookmark_tabs:

Considerando que já existe uma tabela onde os endereços com má reputação estão inseridos e uma outra onde registra em tempo real as conexões oriundas de IPs públicos, faz-se necessária a concatenação desses endereços para uma análise mais detalhada, caso o edereço não esteja diretamente nessa lista.

Além disso, é necessário adicionar a regra de firewall que será executada.

Essa execução será tabém executada através de rotina, adicionando as seguintes linhas no arquivo /etc/crontab, que ficará da seguinte forma:

```bash

SHELL=/bin/bash
API_KEY='API_KEY_ABUSEIPDB'

0 0,12 * * * python3 /opt/FIBRA-UECE/blacklist/update-bl.py

0,10,22,30,40,50 * * * * /opt/FIBRA-UECE/python/bin/python3 /opt/FIBRA-UECE/tarpit/tarpit-in3.py >> /var/log/tarpit.log 2>&1

5,15,25,35,45,55 * * * * /opt/FIBRA-UECE/python/bin/python3 /opt/FIBRA-UECE/firewall/rules.py >> /var/log/rules-fw.log 2>&1

* * * * * /opt/FIBRA-UECE/checkService.sh
```

### 5. Ajustando o dashboard :chart_with_upwards_trend:

O dashboard necessário para exibição da solução é o arquivo *Conexões.json*. Para seu uso, basta acessar ```https://IP_Do_Servidor:3000```. Na interface do grafana, logar com as credenciais iniciais ```admin/admin``` e atlerar a senha à critério.

Depois, apontar o datasource da solução, navegando em:

```
Connections > Add connection > procurar por PostgreSQL > Create a PostgreSQL data source
```

Na criação do data source, basta fazer as seguintes alterações, baseadas nas configurações do docker compose:

**Host:** ```postgres```
**Database:** ```firewall``` 
**Username:** ```admin```
**Password:** ```Q1w2e3r4```
**TLS/SSL Mode:** ```disable```

Depois do data source criado, é necessária a importação do arquivo JSON para visualização do dashboard.

```
Dashboards > New > Import > Upload dashboard JSON file
```

Em seguida, basta clicar em ```Load```.


**E é isso. Após esses passos a ferramenta está configurada, pronta pra uso e exibindo os dados.**