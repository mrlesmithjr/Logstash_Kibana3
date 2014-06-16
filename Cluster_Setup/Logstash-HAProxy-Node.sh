#!/bin/bash

#Provided by @mrlesmithjr
#EveryThingShouldBeVirtual.com

# This script will install logstash to listen on UDP/514 and sort out some types of devices that do not support sending syslog to a TCP port.
# Logstash will join the elasticsearch logstash-cluster as a client and output everything into the cluster
# Install this script on your frontend HAProxy Nodes. Because all devices will point to the VIP of HAProxy only the active node will receive syslog messages
# This will also support HAProxy cluster failover

set -e

# Setup logging
# Logs stderr and stdout to separate files.
exec 2> >(tee "./Logstash_Kibana3/install_logstash_haroxy_node_ubuntu.err")
exec > >(tee "./Logstash_Kibana3/install_logstash_haroxy_node_ubuntu.log")

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
apt-get install -y --force-yes openjdk-7-jre-headless git curl nginx

# Install Logstash
cd /opt
wget https://download.elasticsearch.org/logstash/logstash/logstash-1.4.1.tar.gz
tar zxvf logstash-*.tar.gz
mv logstash-1.4.1 logstash
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
input {
        udp {
                type => "syslog"
                port => "514"
        }
}
filter {
        if [type] == "syslog" {
                dns {
                        reverse => [ "host" ] action => "replace"
                }
                mutate {
                        add_tag => [ "syslog-UDP" ]
                }
                if [host] =~ /.*?(nsvpx).*?($yourdomainname)?/ {
                        mutate {
                                add_tag => [ "Netscaler", "Ready" ]
                        }
                }
                if [host] =~ /.*?($pfsensehostname).*?($yourdomainname)?/ {
                        mutate {
                                add_tag => [ "PFSense", "Ready" ]
                        }
                }
                if "Ready" not in [tags] {
                        mutate {
                                add_tag => [ "syslog" ]
                        }
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
filter {
        if "syslog" in [tags] {
                grok {
                        match => { "message" => "<%{POSINT:syslog_pri}>%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
                        add_field => [ "received_at", "%{@timestamp}" ]
                        add_field => [ "received_from", "%{host}" ]
                }
                syslog_pri { }
                date {
                        match => [ "syslog_timestamp", "MMM d HH:mm:ss", "MMM dd HH:mm:ss" ]
                }
                if !("_grokparsefailure" in [tags]) {
                        mutate {
                                replace => [ "@source_host", "%{syslog_hostname}" ]
                                replace => [ "@message", "%{syslog_message}" ]
                        }
                }
                mutate {
                        remove_field => [ "syslog_hostname", "syslog_message", "syslog_timestamp" ]
                }
                if "_grokparsefailure" in [tags] {
                        drop { }
                }
        }
}
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
                        }
                        mutate {
                                replace => [ "host", "%{@source_host}" ]
                        }
                        mutate {
                                rename => [ "http_status_code", "response" ]
                        }
                        mutate {
                                rename => [ "http_request", "request" ]
                        }
                        mutate {
                                rename => [ "client_ip", "clientip" ]
                        }
                }
        }
}
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
                mutate {
                        replace => [ "@source_host", "%{host}" ]
                }
                mutate {
                        replace => [ "@message", "%{netscaler_message}" ]
                }
                geoip {
                        source => "clientip"
                        target => "geoip"
                        add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
                        add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
                }
                mutate {
                        convert => [ "[geoip][coordinates]", "float" ]
                }
        }
}
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
        }
        mutate {
            replace => [ "message", "%{msg}" ]
        }
        mutate {
            remove_field => [ "msg", "datetime" ]
        }
    }
    if [prog] =~ /^pf$/ {
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
            match => [ "message", "rule (?<rule>.*)\(.*\): (?<action>pass|block) .* on (?<iface>.*): .* proto (?<proto>TCP|UDP|IGMP|ICMP) .*\n\s*(?<src_ip>(\d+\.\d+\.\d+\.\d+))\.?(?<src_port>(\d*)) [<|>] (?<dest_ip>(\d+\.\d+\.\d+\.\d+))\.?(?<dest_port>(\d*)):" ]
        }
    }
    if [prog] =~ /^dhcpd$/ {
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
                        replace => [ "@source_host", "%{host}" ]
                }
                mutate {
                        replace => [ "@message", "%{message}" ]
                }
        }
}
filter {
        if [type] =~ "nginx" {
                grok {
                        pattern => "%{COMBINEDAPACHELOG}"
                }
        }
}
output {
        if [type] !~ "nginx" {
                elasticsearch {
                        cluster => "logstash-cluster"
                        flush_size => 1
                        template_overwrite => true
                        manage_template => true
                        template => "/opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json"
                }
        }
}
output {
        if [type] =~ "nginx" {
                redis {
                        host => "logstash"
                        data_type => "list"
                        key => "logstash"
                }
        }
}
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

# Logrotate job for logstash
tee -a /etc/logrotate.d/logstash <<EOF
/var/log/logstash.log {
        monthly
        rotate 12
        compress
        delaycompress
        missingok
        notifempty
        create 644 root root
}
EOF

# All Done
echo "Installation has completed!!"
echo "${yellow}EveryThingShouldBeVirtual.com${NC}"
echo "${yellow}@mrlesmithjr${NC}"
echo "${yellow}Enjoy!!!${NC}"
