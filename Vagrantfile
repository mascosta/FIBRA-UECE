#################################################################################################################################
#																
# Script Name: Vagrantfile													
# 
# Description: A code to provision 3 VMs for kube local labs 				
# Author: Marcus Costa														
# Email Address: marcus.asc@gmail.com												
# Execution Sample: Just "vagrant up" :)									
# 
#################################################################################################################################

# Some variables

$route_ip = "${GATEWAY_IP_ADDRESS}"        # Configure to your environment gateway ip address
$brdg_int = "${INTERFACE_NAME}"       # Configure to your environment NIC adapter

Vagrant.configure("2") do |config|
    # Setting up the quantity of VM's will be configured, in this case, 1 to 4.
            # Using the number of VM "i" to compose it VirtualBox name.
    config.vm.define "srvdsrt" do |srvdsrt|
        srvdsrt.vm.box = "debian/bookworm64"
        # Using the number of VM "i" to compose it hostname
        srvdsrt.vm.hostname = "srvdsrt"
        srvdsrt.vm.network "public_network", 
            bridge: "#{$brdg_int}" 
        srvdsrt.vm.provider "virtualbox" do |v| 
            v.memory    = 3000
            v.cpus      = 4
            v.name      = "srvdsrt"
        end
        srvdsrt.vm.provision "shell",
            run: "always",
            inline: "ip route del default"    
        srvdsrt.vm.provision "shell",
            run: "always",
            inline: "ip route add default via #{$route_ip}"
        srvdsrt.vm.provision "shell", inline: <<-SHELL
            sudo apt update -y && \
            sudo apt install vim wget bash-completion tcpdump net-tools curl telnet nmap zip git unzip python3-pip python3-venv -y && \
            sudo curl -fsSL https://get.docker.com | bash && \
            sudo mkdir -p /opt/dissertacao/docker/postgres/data && \
            sudo mkdir -p /opt/dissertacao/docker/grafana && \
            sudo mkdir -p /opt/dissertacao/python && \
            sudo chmod 777 -R /opt/dissertacao/ && \
            sudo python3 -m venv /opt/dissertacao/python/ && \
            sudo wget https://github.com/maxmind/geoipupdate/releases/download/v6.1.0/geoipupdate_6.1.0_linux_amd64.deb && \
            sudo apt clean 
        SHELL
        srvdsrt.vm.provision "shell", 
            run: "always", 
            inline: "sudo chmod 777 -R /opt/dissertacao/ "
        srvdsrt.vm.provision "file", 
            source: "./docker-compose.yaml", 
            destination: "/opt/dissertacao/docker/docker-compose.yaml"
        srvdsrt.vm.provision "file", 
            source: "./collect-pgsql-ipv4.py", 
            destination: "/opt/dissertacao/python/scripts/collect-pgsql-ipv4.py"
        srvdsrt.vm.provision "file", 
            source: "./collect-pgsql.py", 
            destination: "/opt/dissertacao/python/scripts/collect-pgsql.py"
    end
    config.vm.define "kali" do |kali|
        kali.vm.box = "kalilinux/rolling"
        kali.vm.hostname = "kali"
        kali.vm.network "public_network", 
            bridge: "#{$brdg_int}" 
        kali.vm.provider "virtualbox" do |v| 
            v.memory    = 2048
            v.cpus      = 3
            v.name      = "kali"
            v.gui       = true
        end
        kali.vm.provision "shell",
            run: "always",
            inline: "ip route del default"    
        kali.vm.provision "shell",
            run: "always",
            inline: "ip route add default via #{$route_ip}"
    end
end

