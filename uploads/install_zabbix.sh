#!/usr/bin/env bash

#centos 6
rpm -ivh http://repo.zabbix.com/zabbix/3.0/rhel/6/x86_64/zabbix-get-3.0.4-1.el6.x86_64.rpm
http://repo.zabbix.com/zabbix/3.0/rhel/6/x86_64/zabbix-java-gateway-3.0.4-1.el6.x86_64.rpm
http://repo.zabbix.com/zabbix/3.0/rhel/6/x86_64/zabbix-proxy-mysql-3.0.4-1.el6.x86_64.rpm
http://repo.zabbix.com/zabbix/3.0/rhel/6/x86_64/zabbix-sender-3.0.4-1.el6.x86_64.rpm
http://repo.zabbix.com/zabbix/3.0/rhel/6/x86_64/zabbix-release-3.0-1.el6.noarch.rpm
http://repo.zabbix.com/zabbix/3.0/rhel/6/x86_64/deprecated/zabbix-web-3.0.4-1.el6.noarch.rpm
http://repo.zabbix.com/zabbix/3.0/rhel/6/x86_64/deprecated/zabbix-web-mysql-3.0.4-1.el6.noarch.rpm

#centos 7
http://repo.zabbix.com/zabbix/3.0/rhel/7/x86_64/zabbix-get-3.0.4-1.el7.x86_64.rpm
http://repo.zabbix.com/zabbix/3.0/rhel/7/x86_64/zabbix-java-gateway-3.0.4-1.el7.x86_64.rpm
http://repo.zabbix.com/zabbix/3.0/rhel/7/x86_64/zabbix-proxy-mysql-3.0.4-1.el7.x86_64.rpm
http://repo.zabbix.com/zabbix/3.0/rhel/7/x86_64/zabbix-sender-3.0.4-1.el7.x86_64.rpm
http://repo.zabbix.com/zabbix/3.0/rhel/7/x86_64/zabbix-server-mysql-3.0.4-1.el7.x86_64.rpm
http://repo.zabbix.com/zabbix/3.0/rhel/7/x86_64/zabbix-web-3.0.4-1.el7.noarch.rpm
http://repo.zabbix.com/zabbix/3.0/rhel/7/x86_64/zabbix-web-mysql-3.0.4-1.el7.noarch.rpm

###update_conf

agent_ipaddress=$1
server_ipaddress=`ip -f inet -o addr show eth0|cut -d\  -f 7 | cut -d/ -f 1`
proxy_ipaddress=$2

zabbix_get -s $agent_ipaddress -k system.run["sed -i -e \"s/^Server=.*/Server="$server_ipaddress"\\\x2C"$proxy_ipaddress"/g\" /etc/zabbix/zabbix_agentd.conf"]
zabbix_get -s $agent_ipaddress -k system.run["sed -i -e \"s/^ServerActive=.*/ServerActive="$proxy_ipaddress"/g\" /etc/zabbix/zabbix_agentd.conf"]
zabbix_get -s $agent_ipaddress -k system.run["sed -i -e \"s/^HostMetadata=.*/HostMetadata=/g\" /etc/zabbix/zabbix_agentd.conf"]

zabbix_get -s $agent_ipaddress -k system.run["service zabbix-agent restart",nowait]