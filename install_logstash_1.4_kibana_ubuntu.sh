#!/bin/bash

#Provided by @mrlesmithjr
#EveryThingShouldBeVirtual.com

set -e
# Setup logging
# Logs stderr and stdout to separate files.
exec 2> >(tee "./Logstash_Kibana3/install_logstash_kibana_ubuntu.err")
exec > >(tee "./Logstash_Kibana3/install_logstash_kibana_ubuntu.log")

# Setting colors for output
red="$(tput setaf 1)"
yellow="$(tput bold ; tput setaf 3)"
NC="$(tput sgr0)"

# Capture your FQDN Domain Name and IP Address
echo "${yellow}Capturing your hostname${NC}"
yourhostname=$(hostname)
echo "${yellow}Capturing your domain name${NC}"
yourdomainname=$(dnsdomainname)
echo "${yellow}Capturing your FQDN${NC}"
yourfqdn=$(hostname -f)
echo "${yellow}Detecting IP Address${NC}"
IPADDY="$(ifconfig | grep -A 1 'eth0' | tail -1 | cut -d ':' -f 2 | cut -d ' ' -f 1)"
echo "Your hostname is currently ${red}$yourhostname${NC}"
echo "Your domain name is currently ${red}$yourdomainname${NC}"
echo "Your FQDN is currently ${red}$yourfqdn${NC}"
echo "Detected IP Address is ${red}$IPADDY${NC}"

# Disable CD Sources in /etc/apt/sources.list
echo "Disabling CD Sources and Updating Apt Packages and Installing Pre-Reqs"
sed -i -e 's|deb cdrom:|# deb cdrom:|' /etc/apt/sources.list
apt-get -qq update

# Install Pre-Reqs
apt-get install -y --force-yes openjdk-7-jre-headless ruby ruby1.9.1-dev libcurl4-openssl-dev git nginx curl dnsmasq

# Install Redis-Server
apt-get -y install redis-server
# Configure Redis-Server to listen on all interfaces
sed -i -e 's|bind 127.0.0.1|bind 0.0.0.0|' /etc/redis/redis.conf
service redis-server restart

# Install Oracle Java 7 **NOT Used - Installing openjdk-7-jre above
# echo "Installing Oracle Java 7"
# add-apt-repository -y ppa:webupd8team/java
# apt-get -qq update
# echo oracle-java7-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections
# apt-get -y install oracle-java7-installer
# apt-get -y install oracle-java8-installer oracle-java8-set-default

# Install Elasticsearch
cd /opt
#wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.1.1.deb
#dpkg -i elasticsearch-1.1.1.deb
#wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.2.1.deb
wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.3.2.deb
dpkg -i elasticsearch-1.3.2.deb

# Configure rsyslog to listen on UDP/514 and redirect back to logstash TCP/514
sed -i -e 's|#$ModLoad imudp|$ModLoad imudp|' /etc/rsyslog.conf
sed -i -e 's|#$UDPServerRun 514|$UDPServerRun 514|' /etc/rsyslog.conf
echo '*.* @@'localhost'' | tee -a  /etc/rsyslog.d/50-default.conf
service rsyslog restart

# Configuring Elasticsearch
### Below is added using install script ###
echo "cluster.name: logstash-cluster" >> /etc/elasticsearch/elasticsearch.yml
echo "node.name: $yourhostname" >> /etc/elasticsearch/elasticsearch.yml
echo "discovery.zen.ping.multicast.enabled: false" >> /etc/elasticsearch/elasticsearch.yml
echo "discovery.zen.ping.unicast.hosts: ["127.0.0.1:[9300-9400]"]" >> /etc/elasticsearch/elasticsearch.yml
echo "node.master: true" >> /etc/elasticsearch/elasticsearch.yml
echo "node.data: true" >> /etc/elasticsearch/elasticsearch.yml
echo "index.number_of_shards: 1" >> /etc/elasticsearch/elasticsearch.yml
echo "index.number_of_replicas: 0" >> /etc/elasticsearch/elasticsearch.yml
echo "bootstrap.mlockall: true" >> /etc/elasticsearch/elasticsearch.yml
echo "script.disable_dynamic: true" >> /etc/elasticsearch/elasticsearch.yml

# Making changes to /etc/security/limits.conf to allow more open files for elasticsearch
mv /etc/security/limits.conf /etc/security/limits.bak
grep -Ev "# End of file" /etc/security/limits.bak > /etc/security/limits.conf
echo "elasticsearch soft nofile 65536" >> /etc/security/limits.conf
echo "elasticsearch hard nofile 65536" >> /etc/security/limits.conf
echo "elasticsearch - memlock unlimited" >> /etc/security/limits.conf
echo "# End of file" >> /etc/security/limits.conf

# Set Elasticsearch to start on boot
sudo update-rc.d elasticsearch defaults 95 10

# Restart Elasticsearch service
service elasticsearch restart

# Install ElasticHQ Plugin to view Elasticsearch Cluster Details http://elastichq.org
# To view these stats connect to http://logstashFQDNorIP:9200/_plugin/HQ/
/usr/share/elasticsearch/bin/plugin -install royrusso/elasticsearch-HQ

# Install elasticsearch Marvel Plugin Details http://www.elasticsearch.org/overview/marvel/
# To view these stats connect to http://logstashFQDNorIP:9200/_plugin/marvel
/usr/share/elasticsearch/bin/plugin -i elasticsearch/marvel/latest

# Install other elasticsearch plugins
# To view paramedic connect to http://logstashFQDNorIP:9200/_plugin/paramedic/index.html
/usr/share/elasticsearch/bin/plugin -install karmi/elasticsearch-paramedic
# To view elasticsearch head connect to http://logstashFQDNorIP:9200/_plugin/head/index.html
/usr/share/elasticsearch/bin/plugin -install mobz/elasticsearch-head

# Install Logstash
cd /opt
#wget https://download.elasticsearch.org/logstash/logstash/logstash-1.4.1.tar.gz
wget https://download.elasticsearch.org/logstash/logstash/logstash-1.4.2.tar.gz
tar zxvf logstash-*.tar.gz
rm logstash-*.tar.gz
mv logstash-1.4.*/ logstash
/opt/logstash/bin/plugin install contrib

# Create Logstash Init Script
(
cat <<'EOF'
#! /bin/sh

### BEGIN INIT INFO
# Provides:          logstash
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start daemon at boot time
# Description:       Enable service provided by daemon.
### END INIT INFO

. /lib/lsb/init-functions

name="logstash"
logstash_bin="/opt/logstash/bin/logstash"
logstash_conf="/etc/logstash/logstash.conf"
logstash_log="/var/log/logstash.log"
pid_file="/var/run/$name.pid"
patterns_path="/etc/logstash/patterns"

start () {
        command="${logstash_bin} -- agent -f $logstash_conf --log ${logstash_log}"

        log_daemon_msg "Starting $name" "$name"
        if start-stop-daemon --start --quiet --oknodo --pidfile "$pid_file" -b -m --exec $command; then
                log_end_msg 0
        else
                log_end_msg 1
        fi
}

stop () {
        log_daemon_msg "Stopping $name" "$name"
        start-stop-daemon --stop --quiet --oknodo --pidfile "$pid_file"
}

status () {
        status_of_proc -p "$pid_file" "$name"
}

case $1 in
        start)
                if status; then exit 0; fi
                start
                ;;
        stop)
                stop
                ;;
        reload)
                stop
                start
                ;;
        restart)
                stop
                start
                ;;
        status)
                status && exit 0 || exit $?
                ;;
        *)
                echo "Usage: $0 {start|stop|restart|reload|status}"
                exit 1
                ;;
esac

exit 0
EOF
) | tee /etc/init.d/logstash

# Make logstash executable
chmod +x /etc/init.d/logstash

# Enable logstash start on bootup
update-rc.d logstash defaults 96 04

echo "Setting up logstash for different host type filtering"
echo "Your domain name:"
echo "(example - yourcompany.com)"
echo -n "Enter your domain name and press enter: "
read yourdomainname
echo "You entered ${red}$yourdomainname${NC}"
echo "Now enter your PFSense Firewall hostname if you use it ${red}(DO NOT include your domain name)${NC}"
echo "If you do not use PFSense Firewall enter ${red}pfsense${NC}"
echo -n "Enter PFSense Hostname: "
read pfsensehostname
echo "You entered ${red}$pfsensehostname${NC}"
echo "Now enter your Citrix Netscaler naming scheme if you use it ${red}(DO NOT include your domain name)${NC}"
echo "For example....Your Netscaler's are named nsvpx01, nsvpx02....Only enter nsvpx for the naming scheme"
echo "If you do not use Citrix Netscaler's enter ${red}netscaler${NC}"
echo -n "Enter Citrix Netscaler Naming scheme: "
read netscalernaming
echo "You entered ${red}$netscalernaming${NC}"

# Create Logstash configuration file
mkdir /etc/logstash
tee -a /etc/logstash/logstash.conf <<EOF
input {
        file {
                path => "/var/log/nginx/access.log"
                type => "nginx-access"
                sincedb_path => "/var/log/.nginxaccesssincedb"
        }
}
input {
        file {
                path => "/var/log/nginx/error.log"
                type => "nginx-error"
                sincedb_path => "/var/log/.nginxerrorsincedb"
        }
}
# Change redis threads count to match the number of cpus of this node
input {
        redis {
                host => "127.0.0.1"
                data_type => "list"
                key => "logstash"
                codec => "json"
                threads => "1"
        }
}
input {
        tcp {
                type => "syslog"
                port => "514"
        }
}
input {
        tcp {
                type => "VMware"
                port => "1514"
        }
}
input {
        tcp {
                type => "vCenter"
                port => "1515"
        }
}
input {
        tcp {
                type => "Netscaler"
                port => "1517"
        }
}
input {
        tcp {
                type => "eventlog"
                port => "3515"
                format => "json"
        }
}
input {
        tcp {
                type => "iis"
                port => "3525"
                codec => "json_lines"
        }
}
filter {
        if [type] == "syslog" {
                dns {
                        reverse => [ "host" ]
                        action => "replace"
                }
                mutate {
                        add_tag => [ "syslog" ]
                }
        }
        if [type] == "VMware" {
                mutate {
                        add_tag => "VMware"
                }
        }
        if [type] == "vCenter" {
                mutate {
                        add_tag => "vCenter"
                }
        }
        if [type] == "PFsense" {
                mutate {
                        add_tag => "PFsense"
                }
        }
        if [type] == "Netscaler" {
                mutate {
                        add_tag => "Netscaler"
                }
        }
        if [type] == "eventlog" {
                mutate {
                        add_tag => [ "WindowsEventLog" ]
                }
        }
        if [type] == "apache" {
                mutate {
                       add_tag => [ "apache" ]
                }
        }
        if [type] =~ "nginx" {
                mutate {
                        add_tag => [ "nginx" ]
                }
        }
        if [type] == "iis" {
                mutate {
                        add_tag => [ "IIS" ]
                }
        }
}
filter {
        if [type] == "syslog" {
                mutate {
                        remove_tag => "Ready"
                }
        }
}
# First layer of normal syslog parsing
filter {
        if "syslog" in [tags] {
                grok {
                        match => { "message" => "<%{POSINT:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
                        add_field => [ "received_at", "%{@timestamp}" ]
                        add_field => [ "received_from", "%{host}" ]
                }
                syslog_pri { }
                date {
                        match => [ "syslog_timestamp", "MMM d HH:mm:ss", "MMM dd HH:mm:ss", "ISO8601" ]
                        timezone => "America/New_York"
                }
                if !("_grokparsefailure" in [tags]) {
                        mutate {
                                replace => [ "host", "%{syslog_hostname}" ]
                                replace => [ "@source_host", "%{syslog_hostname}" ]
                                replace => [ "@message", "%{syslog_message}" ]
                        }
                }
                if [syslog_hostname] =~ /.*?($netscalernaming).*?($yourdomainname)?/ {
                        mutate {
                                add_tag => [ "Netscaler" ]
                        }
                }
                if [syslog_hostname] =~ /.*?($pfsensehostname).*?($yourdomainname)?/ {
                        mutate {
                                add_tag => [ "PFSense" ]
                        }
                }
        }
}
# Setting up IPTables firewall parsing
filter {
        if "syslog" in [tags] {
                if "IPTables" in [message] {
                        grok {
                                match => { "message" => "%{IPTABLES}" }
                                patterns_dir => [ "/opt/logstash/patterns" ]
                        }
                        mutate {
                                add_tag => [ "IPTABLES" ]
                        }
                        geoip {
                                source => "src_ip"
                                target => "geoip"
                                add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                                add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                        }
                        mutate {
                                convert => [ "[geoip][coordinates]", "float" ]
                        }
                }
        }
}
# Setting up IPTables actions
filter {
        if "IPTABLES" in [tags] {
                grok {
                        match => [
                                "message", "IPTables-%{WORD:iptables_action}"
                        ]
                }
                grok {
                        match => [
                                "message", "PROTO=%{WORD:iptables_proto}"
                        ]
                }
                mutate {
                        remove_field => [ "proto" ]
                }
                mutate {
                        rename => [ "iptables_proto", "proto" ]
                }
        }
}
# Setting up HAProxy parsing
filter {
        if "syslog" in [tags] {
                if [syslog_program] == "haproxy" {
                        grok {
                                break_on_match => false
                                match => [
                                        "message", "%{HAPROXYHTTP}",
                                        "message", "%{HAPROXYTCP}"
                                ]
                                add_tag => [ "HAProxy" ]
                        }
                        geoip {
                                source => "client_ip"
                                target => "geoip"
                                add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                                add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                        }
                        mutate {
                                convert => [ "[geoip][coordinates]", "float" ]
                                replace => [ "host", "%{@source_host}" ]
                                rename => [ "http_status_code", "response" ]
                                rename => [ "http_request", "request" ]
                                rename => [ "client_ip", "src_ip" ]
                        }
                }
        }
}
# Setting up KeepAliveD parsing
filter {
        if "syslog" in [tags] {
                if [syslog_program] =~ /Keepalived/ {
                        mutate {
                                add_tag => [ "KeepAliveD" ]
                        }
                }
        }
}
# Filtering for SSH logins either failed or successful
filter {
        if "syslog" in [tags] {
                if [syslog_program] == "sshd" {
                        if "Failed password" in [message] {
                                grok {
                                        break_on_match => false
                                        match => [
                                                "message", "invalid user %{DATA:UserName} from %{IP:src_ip}",
                                                "message", "for %{DATA:UserName} from %{IP:src_ip}"
                                        ]
                                }
                                mutate {
                                        add_tag => [ "SSH_Failed_Login" ]
                                }
                        }
                        if "Accepted password" in [message] {
                                grok {
                                        match => [
                                                "message", "for %{DATA:UserName} from %{IP:src_ip}"
                                        ]
                                }
                                mutate {
                                        add_tag => [ "SSH_Successful_Login" ]
                                }
                        }
                        geoip {
                                source => "src_ip"
                                target => "geoip"
                                add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                                add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                        }
                        mutate {
                                convert => [ "[geoip][coordinates]", "float" ]
                        }
                }
        }
}
# Setting up VMware ESX(i) log parsing
filter {
        if "VMware" in [tags] {
                multiline {
                        pattern => "-->"
                        what => "previous"
                }
                grok {
                        break_on_match => true
                        match => [
                                "message", "<%{POSINT:syslog_pri}>%{TIMESTAMP_ISO8601:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{SYSLOGPROG:syslog_program}: (?<message-body>(?<message_system_info>(?:\[%{DATA:message_thread_id} %{DATA:syslog_level} \'%{DATA:message_service}\'\ ?%{DATA:message_opID}])) \[%{DATA:message_service_info}]\ (?<syslog_message>(%{GREEDYDATA})))",
                                "message", "<%{POSINT:syslog_pri}>%{TIMESTAMP_ISO8601:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{SYSLOGPROG:syslog_program}: (?<message-body>(?<message_system_info>(?:\[%{DATA:message_thread_id} %{DATA:syslog_level} \'%{DATA:message_service}\'\ ?%{DATA:message_opID}])) (?<syslog_message>(%{GREEDYDATA})))",
                                "message", "<%{POSINT:syslog_pri}>%{TIMESTAMP_ISO8601:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{SYSLOGPROG:syslog_program}: %{GREEDYDATA:syslog_message}"
                        ]
                }
                syslog_pri { }
                date {
                        match => [ "syslog_timestamp", "YYYY-MM-ddHH:mm:ss,SSS", "ISO8601" ]
                        timezone => "UTC"
                }
                mutate {
                        replace => [ "@source_host", "%{syslog_hostname}" ]
                }
                mutate {
                        replace => [ "@message", "%{syslog_message}" ]
                }
                if "Device naa" in [message] {
                        grok {
                                break_on_match => false
                                match => [
                                        "message", "Device naa.%{WORD:device_naa} performance has %{WORD:device_status}%{GREEDYDATA} of %{INT:datastore_latency_from}%{GREEDYDATA} to %{INT:datastore_latency_to}",
                                        "message", "Device naa.%{WORD:device_naa} performance has %{WORD:device_status}%{GREEDYDATA} from %{INT:datastore_latency_from}%{GREEDYDATA} to %{INT:datastore_latency_to}"
                                ]
                        }
                }
                if "connectivity issues" in [message] {
                        grok {
                                match => [
                                        "message", "Hostd: %{GREEDYDATA} : %{DATA:device_access} to volume %{DATA:device_id} %{DATA:datastore} (following|due to)"
                                ]
                        }
                }
                if "WARNING" in [message] {
                        grok {
                                match => [
                                        "message", "WARNING: %{GREEDYDATA:vmware_warning_msg}"
                                ]
                        }
                }
        }
}
# Setting up VMware vCenter parsing
filter {
        if "vCenter" in [tags] {
                grok {
                        break_on_match => true
                        match => [
                                "message", "<%{INT:syslog_pri}>%{SYSLOGTIMESTAMP} %{IPORHOST:syslog_hostname} %{TIMESTAMP_ISO8601:syslog_timestamp} (?<message-body>(?<message_system_info>(?:\[%{DATA:message_thread_id} %{DATA:syslog_level} \'%{DATA:message_service}\'\ ?%{DATA:message_opID}])) \[%{DATA:message_service_info}]\ (?<syslog_message>(%{GREEDYDATA})))",
                                "message", "<%{INT:syslog_pri}>%{SYSLOGTIMESTAMP} %{IPORHOST:syslog_hostname} %{TIMESTAMP_ISO8601:syslog_timestamp} (?<message-body>(?<message_system_info>(?:\[%{DATA:message_thread_id} %{DATA:syslog_level} \'%{DATA:message_service}\'\ ?%{DATA:message_opID}])) (?<syslog_message>(%{GREEDYDATA})))",
                                "message", "<%{INT:syslog_pri}>%{SYSLOGTIMESTAMP} %{IPORHOST:syslog_hostname} %{TIMESTAMP_ISO8601:syslog_timestamp} %{GREEDYDATA:syslog_message}"
                        ]
                }
                syslog_pri { }
                date {
                        match => [ "syslog_timestamp", "YYYY-MM-ddHH:mm:ss,SSS", "ISO8601" ]
                        timezone => "UTC"
                }
                mutate {
                        replace => [ "@source_host", "%{syslog_hostname}" ]
                        replace => [ "@message", "%{syslog_message}" ]
                }
        }
}
# Setting up PFsense Firewall parsing
filter {
    if "PFSense" in [tags] {
        grok {
            add_tag => [ "firewall" ]
            match => [ "message", "<(?<evtid>.*)>(?<datetime>(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(?:(?:0[1-9])|(?:[12][0-9])|(?:3[01])|[1-9]) (?:2[0123]|[01]?[0-9]):(?:[0-5][0-9]):(?:[0-5][0-9])) (?<prog>.*?): (?<msg>.*)" ]
        }
        mutate {
            gsub => ["datetime","  "," "]
        }
        date {
                match => [ "datetime", "MMM dd HH:mm:ss" ]
                timezone => "America/New_York"
        }
        mutate {
            replace => [ "message", "%{msg}" ]
        }
        mutate {
            remove_field => [ "msg", "datetime", "prog" ]
        }
    }
    if [syslog_program] =~ /^pf$/ {
        mutate {
            add_tag => [ "packetfilter" ]
        }
        multiline {
            pattern => "^\s+|^\t\s+"
            what => "previous"
        }
        mutate {
            remove_field => [ "msg", "datetime" ]
            remove_tag => [ "multiline" ]
        }
        grok {
            match => [ "message", "rule (?<rule>.*)\(.*\): (?<action>pass|block) .* on (?<iface>.*): .* proto (?<proto>TCP|UDP|IGMP|ICMP) .*\n\s*(?<src_ip>(\d+\.\d+\.\d+\.\d+))\.?(?<src_port>(\d*)) [<|>] (?<dst_ip>(\d+\.\d+\.\d+\.\d+))\.?(?<dst_port>(\d*)):" ]
        }
    }
    if [syslog_program] =~ /^dhcpd$/ {
        if [message] =~ /^DHCPACK|^DHCPREQUEST|^DHCPOFFER/ {
            grok {
                match => [ "message", "(?<action>.*) (on|for|to) (?<src_ip>[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9]) .*(?<mac_address>[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]).* via (?<iface>.*)" ]
            }
        }
        if [message] =~ /^DHCPDISCOVER/ {
            grok {
                match => [ "message", "(?<action>.*) from (?<mac_address>[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]:[0-9a-fA-F][0-9a-fA-F]).* via (?<iface>.*)" ]
            }
        }
        if [message] =~ /^DHCPINFORM/ {
            grok {
                match => [ "message", "(?<action>.*) from (?<src_ip>.*).* via (?<iface>.*)" ]
            }
        }
   }
   if "_grokparsefailure" in [tags] {
        drop { }
   }
}
filter {
        if "PFSense" in [tags] {
                mutate {
                        replace => [ "@source_host", "%{syslog_hostname}" ]
                        replace => [ "@message", "%{syslog_message}" ]
                }
        }
}
# Setting up Citrix Netscaler parsing
filter {
        if "Netscaler" in [tags] {
                grok {
                        break_on_match => true
                        match => [
                                "message", "<%{POSINT:syslog_pri}> %{DATE_US}:%{TIME} GMT %{SYSLOGHOST:syslog_hostname} %{GREEDYDATA:netscaler_message} : %{DATA} %{INT:netscaler_spcbid} - %{DATA} %{IP:clientip} - %{DATA} %{INT:netscaler_client_port} - %{DATA} %{IP:netscaler_vserver_ip} - %{DATA} %{INT:netscaler_vserver_port} %{GREEDYDATA:netscaler_message} - %{DATA} %{WORD:netscaler_session_type}",
                                "message", "<%{POSINT:syslog_pri}> %{DATE_US}:%{TIME} GMT %{SYSLOGHOST:syslog_hostname} %{GREEDYDATA:netscaler_message}"
                        ]
                }
                syslog_pri { }
                geoip {
                        source => "clientip"
                        target => "geoip"
                        add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                        add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                }
                mutate {
                        add_field => [ "src_ip", "%{clientip}" ]
                        convert => [ "[geoip][coordinates]", "float" ]
                        replace => [ "@source_host", "%{host}" ]
                        replace => [ "@message", "%{netscaler_message}" ]
                }
        }
}
# Setting up Apache web server parsing
filter {
        if [type] == "apache" {
                grok {
                        pattern => "%{COMBINEDAPACHELOG}"
                }
                geoip {
                        source => "clientip"
                        target => "geoip"
                        add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                        add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                }
                date {
                        match => [ "timestamp" , "dd/MMM/yyyy:HH:mm:ss Z" ]
                }
                mutate {
                        add_field => [ "src_ip", "%{clientip}" ]
                        convert => [ "[geoip][coordinates]", "float" ]
                        replace => [ "@source_host", "%{host}" ]
                        replace => [ "@message", "%{message}" ]
                        rename => [ "verb" , "method" ]
                }
                grok {
                        match => [
                                "message", "%{DATA:apache_vhost} "
                        ]
                }
        }
}
# Setting up Nginx web server parsing
filter {
        if [type] =~ "nginx" {
                grok {
                        pattern => "%{COMBINEDAPACHELOG}"
                }
                geoip {
                        source => "clientip"
                        target => "geoip"
                        add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                        add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                }
                date {
                        match => [ "timestamp" , "dd/MMM/yyyy:HH:mm:ss Z" ]
                }
                mutate {
                        add_field => [ "src_ip", "%{clientip}" ]
                        convert => [ "[geoip][coordinates]", "float" ]
                        replace => [ "@source_host", "%{host}" ]
                        replace => [ "@message", "%{message}" ]
                        rename => [ "verb" , "method" ]
                }
                grok {
                        match => [
                                "message", "%{DATA:apache_vhost} "
                        ]
                }
        }
}
# Setting up Nginx errors parsing
filter {
        if [type] == "nginx-error" {
                grok {
                        match => [
                                "message", "(?<timestamp>%{YEAR}[./-]%{MONTHNUM}[./-]%{MONTHDAY}[- ]%{TIME}) \[%{LOGLEVEL:severity}\] %{POSINT:pid}#%{NUMBER}: %{GREEDYDATA:errormessage}(?:, client: (?<clientip>%{IP}|%{HOSTNAME}))(?:, server: %{IPORHOST:server})(?:, request: %{QS:request}) ??(?:, host: %{QS:host})",
                                "message", "(?<timestamp>%{YEAR}[./-]%{MONTHNUM}[./-]%{MONTHDAY}[- ]%{TIME}) \[%{LOGLEVEL:severity}\] %{POSINT:pid}#%{NUMBER}: %{GREEDYDATA:errormessage}(?:, client: (?<clientip>%{IP}|%{HOSTNAME}))(?:, server: %{IPORHOST:server})(?:, request: %{QS:request})(?:, upstream: %{QS:upstream})(?:;, host: %{QS:host})(?:, referrer: \"%{URI:referrer})"
                        ]
                }
        }
}
# Windows Eventlogs....Use NXLOG for client side logging
filter {
        if [type] == "eventlog" {
                grep {
                        match => { "EventReceivedTime"  => "\d+"}
                }
                mutate {
                        lowercase => [ "EventType", "FileName", "Hostname", "Severity" ]
                }
                mutate {
                        rename => [ "Hostname", "@source_host" ]
                }
                date {
                        match => [ "EventReceivedTime", "UNIX" ]
                }
                mutate {
                        rename => [ "Message", "@message" ]
#                        rename => [ "Severity", "eventlog_severity" ]
#                        rename => [ "SeverityValue", "eventlog_severity_code" ]
#                        rename => [ "Channel", "eventlog_channel" ]
#                        rename => [ "SourceName", "eventlog_program" ]
#                        rename => [ "SourceModuleName", "nxlog_input" ]
#                        rename => [ "Category", "eventlog_category" ]
#                        rename => [ "EventID", "eventlog_id" ]
#                        rename => [ "RecordNumber", "eventlog_record_number" ]
#                        rename => [ "ProcessID", "eventlog_pid" ]
                }
        }
}
# Microsoft IIS logging....Use NXLOG for client side logging
filter {
        if [type] == "iis" {
                if [message] =~ "^#" {
                                drop {}
                }
                grok {
                        match => [
                                "message", "%{TIMESTAMP_ISO8601:logtime} %{IPORHOST:hostname} %{URIPROTO:cs_method} %{URIPATH:cs_stem} (?:%{NOTSPACE:cs_query}|-) %{NUMBER:src_port} %{NOTSPACE:cs_username} %{IP:clientip} %{NOTSPACE:cs_useragent} %{NUMBER:sc_status} %{NUMBER:sc_subresponse} %{NUMBER:sc_win32_status} %{NUMBER:timetaken}"
                        ]
                }
                date {
                        match => [ "logtime", "YYYY-MM-dd HH:mm:ss" ]
                        timezone => "UTC"
                }
                geoip {
                        source => "clientip"
                        target => "geoip"
                        add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                        add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                }
                dns {
                        reverse => [ "hostname" ]
                        action => "replace"
                }
                mutate {
                        add_field => [ "src_ip", "%{clientip}" ]
                        convert => [ "[geoip][coordinates]", "float" ]
                        replace => [ "@source_host", "%{hostname}" ]
                        replace => [ "@message", "%{message}" ]
                        rename => [ "cs_method", "method" ]
                        rename => [ "cs_stem", "request" ]
                        rename => [ "cs_useragent", "agent" ]
                        rename => [ "cs_username", "username" ]
                        rename => [ "sc_status", "response" ]
                        rename => [ "timetaken", "time_request" ]
                }
        }
}
# Create @source_host_ip field for all devices for IP Tracking used along with src_ip and dst_ip fields
filter {
        if ![source_host_ip] {
                mutate {
                        add_field => [ "source_host_ip", "%{@source_host}" ]
                }
                dns {
                        resolve => [ "source_host_ip" ]
                        action => "replace"
                }
                mutate {
                        rename => [ "source_host_ip", "@source_host_ip" ]
                }
        }
}
# The below filter section will be used to remove unnecessary fields to keep ES memory cache from filling up with useless data
# The below filter section will be where you would want to comment certain types or tags out if trying to isolate a logging issue
filter {
        if [type] == "apache" {
                mutate {
                        remove_field => [ "clientip", "host" ]
                }
        }
        if [type] == "eventlog" {
                mutate {
                        remove => [ "EventReceivedTime", "host" ]
                }
        }
        if "HAProxy" in [tags] {
                mutate {
                        remove_field => [ "haproxy_hour", "haproxy_milliseconds", "haproxy_minute", "haproxy_month", "haproxy_monthday", "haproxy_second", "haproxy_year", "pid", "program", "syslog_server" ]
                }
        }
        if [type] == "iis" {
                mutate {
                        remove_field => [ "clientip", "host", "hostname", "logtime" ]
                }
        }
        if [type] =~ "nginx" {
                mutate {
                        remove_field => [ "clientip", "host" ]
                }
        }
        if "Netscaler" in [tags] {
                mutate {
                        remove_field => [ "clientip" ]
                }
        }
        if [type] == "syslog" {
                mutate {
                        remove_field => [ "host", "received_at", "received_from", "syslog_hostname", "syslog_message" ]
                }
        }
        if [type] == "VMware" {
                mutate {
                        remove_field => [ "host", "message-body", "program", "syslog_hostname", "syslog_message" ]
                }
        }
        if [type] == "vCenter" {
                mutate {
                        remove_field => [ "host", "message-body", "program", "syslog_hostname", "syslog_message", "syslog_timestamp" ]
                }
        }
}
#### All in One install mode ####
# Send output to local elasticsearch instance
# Change to one of the other modes and comment out below if needed
output {
        elasticsearch_http {
                host => "127.0.0.1"
                flush_size => 1
		template_overwrite => true
                manage_template => true
                template => "/opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json"
        }
}
#### Multicast discovery mode ####
# Send output to the ES cluster logstash-cluster using a predefined template
# The following settings will be used during the initial setup which will be used for using multicast ES nodes
# When changing to unicast discovery mode you need to comment out the following section and configure the unicast discovery mode in the next section
#output {
#        elasticsearch {
#                cluster => "logstash-cluster"
#                flush_size => 1
#                manage_template => true
#                template => "/opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json"
#        }
#}
#### Unicast discovery mode ####
# Send output to the ES cluster logstash-cluster using a predefined template
# The settings below will be used when you change to unicast discovery mode for all ES nodes
# Make sure to comment out the above multicast discovery mode section
#output {
#        elasticsearch {
#                cluster => "logstash-cluster"
#                host => "logstash"
#                port => "9300"
#                protocol => "node"
#                flush_size => "1"
#                manage_template => true
#                template_overwrite => true
#                template => "/opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json"
#        }
#}
EOF

# Update elasticsearch-template for logstash
mv /opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json /opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json.orig
tee -a /opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json <<EOF
{
  "template" : "logstash-*",
  "settings" : {
    "index.refresh_interval" : "5s"
  },
  "mappings" : {
    "_default_" : {
       "_all" : {"enabled" : true},
       "dynamic_templates" : [ {
         "string_fields" : {
           "match" : "*",
           "match_mapping_type" : "string",
           "mapping" : {
             "type" : "string", "index" : "analyzed", "omit_norms" : true,
               "fields" : {
                 "raw" : {"type": "string", "index" : "not_analyzed", "ignore_above" : 256}
               }
           }
         }
       } ],
       "properties" : {
         "@version": { "type": "string", "index": "not_analyzed" },
         "geoip"  : {
           "type" : "object",
             "dynamic": true,
             "path": "full",
             "properties" : {
               "location" : { "type" : "geo_point" }
             }
         },
        "actconn": { "type": "integer", "index": "not_analyzed" },
        "backend_queue": { "type": "integer", "index": "not_analyzed" },
        "beconn": { "type": "integer", "index": "not_analyzed" },
        "bytes": { "type": "long", "index": "not_analyzed" },
        "bytes_read": { "type": "long", "index": "not_analyzed" },
        "datastore_latency_from": { "type": "long", "index": "not_analyzed" },
        "datastore_latency_to": { "type": "long", "index": "not_analyzed" },
        "feconn": { "type": "integer", "index": "not_analyzed" },
        "response_time": { "type": "long", "index": "not_analyzed" },
        "srv_queue": { "type": "integer", "index": "not_analyzed" },
        "srvconn": { "type": "integer", "index": "not_analyzed" },
        "time_backend_connect": { "type": "integer", "index": "not_analyzed" },
        "time_backend_response": { "type": "long", "index": "not_analyzed" },
        "time_duration": { "type": "long", "index": "not_analyzed" },
        "time_queue": { "type": "integer", "index": "not_analyzed" },
        "time_request": { "type": "integer", "index": "not_analyzed" }
       }
    }
  }
}
EOF

# Create IPTables Grok pattern
tee -a /opt/logstash/patterns/IPTABLES <<EOF
NETFILTERMAC %{COMMONMAC:dst_mac}:%{COMMONMAC:src_mac}:%{ETHTYPE:ethtype}
ETHTYPE (?:(?:[A-Fa-f0-9]{2}):(?:[A-Fa-f0-9]{2}))
IPTABLES1 (?:IN=%{WORD:in_device} OUT=(%{WORD:out_device})? MAC=%{NETFILTERMAC} SRC=%{IP:src_ip} DST=%{IP:dst_ip}.*(TTL=%{INT:ttl})?.*PROTO=%{WORD:proto}?.*SPT=%{INT:src_port}?.*DPT=%{INT:dst_port}?.*)
IPTABLES2 (?:IN=%{WORD:in_device} OUT=(%{WORD:out_device})? MAC=%{NETFILTERMAC} SRC=%{IP:src_ip} DST=%{IP:dst_ip}.*(TTL=%{INT:ttl})?.*PROTO=%{INT:proto}?.*)
IPTABLES (?:%{IPTABLES1}|%{IPTABLES2})
EOF

# Restart logstash service
service logstash restart

# The below is required for Ubuntu 14.04 Desktop version as nginx sets root to /usr/share/nginx/wwww
if [ ! -d "/usr/share/nginx/html" ]; then
	mkdir /usr/share/nginx/html
	sed -i -e 's|root /usr/share/nginx/www|root /usr/share/nginx/html|' /etc/nginx/sites-enabled/default
fi

# Install and configure Kibana3 frontend
cd /usr/share/nginx/html
#wget https://download.elasticsearch.org/kibana/kibana/kibana-3.1.0.tar.gz
wget https://download.elasticsearch.org/kibana/kibana/kibana-3.1.1.tar.gz
tar zxvf kibana-*
rm kibana-*.tar.gz
mv kibana-* kibana

# Making the logstash dashboard the default
mv /usr/share/nginx/html/kibana/app/dashboards/default.json /usr/share/nginx/html/kibana/app/dashboards/default.json.orig
mv /usr/share/nginx/html/kibana/app/dashboards/logstash.json /usr/share/nginx/html/kibana/app/dashboards/default.json

# Restart NGINX
service nginx restart

# Install elasticsearch curator http://www.elasticsearch.org/blog/curator-tending-your-time-series-indices/
apt-get -y install python-pip
pip install elasticsearch-curator

# Create /etc/cron.daily/elasticsearch_curator Cron Job and send output to logstash tagged as curator
tee -a /etc/cron.daily/elasticsearch_curator <<EOF
#!/bin/sh
curator delete --older-than 90 2>&1 | nc logstash 28778
curator close --older-than 30 2>&1 | nc logstash 28778
curator bloom --older-than 2 2>&1 | nc logstash 28778
curator optimize --older-than 2 2>&1 | nc logstash 28778

# Cleanup Marvel plugin indices
curator delete --older-than 60 -p .marvel- 2>&1 | nc logstash 28778
curator close --older-than 7 -p .marvel- 2>&1 | nc logstash 28778
curator bloom --older-than 2 -p .marvel- 2>&1 | nc logstash 28778
curator optimize --older-than 2 -p .marvel- 2>&1 | nc logstash 28778 

# Email report
#recipients="emailAdressToReceiveReport"
#subject="Daily Elasticsearch Curator Job Report"
#cat /var/log/elasticsearch_curator.log | mail -s $subject $recipients
EOF

# Make elasticsearch_curator executable
chmod +x /etc/cron.daily/elasticsearch_curator

# Logrotate job for elasticsearch_curator
tee -a /etc/logrotate.d/elasticsearch_curator <<EOF
/var/log/elasticsearch_curator.log {
        monthly
        rotate 12
        compress
        delaycompress
        missingok
        notifempty
        create 644 root root
}
EOF
# Logrotate job for elasticsearch_curator
tee -a /etc/logrotate.d/elasticsearch_curator <<EOF
/var/log/elasticsearch_curator.log {
        monthly
        rotate 12
        compress
        delaycompress
        missingok
        notifempty
        create 644 root root
}
EOF

# Modify Elasticsearch Marvel plugin settings...Default template creates 1 replica but this install only installs one ES node so we will disable replicas
curl -XPUT localhost:9200/_template/marvel_custom -d '
{
    "order" : 1,
    "template" : ".marvel*",
    "settings" : {
        "number_of_replicas" : 0
    }
}'

# All Done
echo "Installation has completed!!"
echo -e "Connect to ${red}http://$yourfqdn/kibana${NC} or ${red}http://$IPADDY/kibana${NC}"
echo "${yellow}EveryThingShouldBeVirtual.com${NC}"
echo "${yellow}@mrlesmithjr${NC}"
echo "${yellow}Enjoy!!!${NC}"
