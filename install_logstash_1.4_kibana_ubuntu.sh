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
echo "${yellow}Capturing your domain name${NC}"
yourdomainname=$(dnsdomainname)
echo "${yellow}Capturing your FQDN${NC}"
yourfqdn=$(hostname -f)
echo "${yellow}Detecting IP Address${NC}"
IPADDY="$(ifconfig | grep -A 1 'eth0' | tail -1 | cut -d ':' -f 2 | cut -d ' ' -f 1)"
echo "Your domain name is currently ${red}$yourdomainname${NC}"
echo "Your FQDN is currently ${red}$yourfqdn${NC}"
echo "Detected IP Address is ${red}$IPADDY${NC}"

# Disable CD Sources in /etc/apt/sources.list
echo "Disabling CD Sources and Updating Apt Packages and Installing Pre-Reqs"
sed -i -e 's|deb cdrom:|# deb cdrom:|' /etc/apt/sources.list
apt-get -qq update

# Install Pre-Reqs
apt-get install -y --force-yes openjdk-7-jre-headless ruby ruby1.9.1-dev libcurl4-openssl-dev git apache2

# Install Redis-Server
apt-get -y install redis-server
# Configure Redis-Server to listen on all interfaces
sed -i -e 's|bind 127.0.0.1|bind 0.0.0.0|' /etc/redis/redis.conf
service redis-server restart

# Install Elasticsearch
cd /opt
wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-0.90.11.deb
dpkg -i elasticsearch-0.90.11.deb

# Configuring Elasticsearch
sed -i '$a\cluster.name: default-cluster' /etc/elasticsearch/elasticsearch.yml
sed -i '$a\node.name: "elastic-master"' /etc/elasticsearch/elasticsearch.yml
sed -i '$a\discovery.zen.ping.multicast.enabled: false' /etc/elasticsearch/elasticsearch.yml
sed -i '$a\discovery.zen.ping.unicast.hosts: ["127.0.0.1:[9300-9400]"]' /etc/elasticsearch/elasticsearch.yml
sed -i '$a\node.master: true' /etc/elasticsearch/elasticsearch.yml
sed -i '$a\node.data: true' /etc/elasticsearch/elasticsearch.yml
sed -i '$a\index.number_of_shards: 1' /etc/elasticsearch/elasticsearch.yml
sed -i '$a\index.number_of_replicas: 0' /etc/elasticsearch/elasticsearch.yml
sed -i '$a\bootstrap.mlockall: true' /etc/elasticsearch/elasticsearch.yml

# Restart Elasticsearch service
service elasticsearch restart

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
update-rc.d logstash defaults

echo "Setting up logstash for ESXi host filtering"
echo "ESXi host naming convention: (example:esxi|esx|other - Only enter common naming)"
echo "(example - esxi01,esxi02, etc. - Only enter esxi)"
echo -n "Enter ESXi host naming convention and press enter: "
read esxinaming
echo "You entered ${red}$esxinaming${NC}"
echo "Your domain name:"
echo "(example - yourcompany.com)"
echo -n "Enter your domain name and press enter: "
read yourdomainname
echo "You entered ${red}$yourdomainname${NC}"

# Create Logstash configuration file
mkdir /etc/logstash
tee -a /etc/logstash/logstash.conf <<EOF
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
			if [host] =~ /.*?($esxinaming).*?($yourdomainname)?/ {
				mutate { add_tag => [ "VMware" ]
				}
			}	
			if [host] !~ /.*?(esxi).*?(everythingshouldbevirtual.local)?/ {
				mutate { add_tag => [ "syslog" ]
				}
			}
		}
}
filter {
	if "syslog" in [tags] {
		grok {
			pattern => [ "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" ]
			add_field => [ "received_at", "%{@timestamp}" ]
			add_field => [ "received_from", "%{@source_host}" ]
		}
		date {
			match => [ "syslog_timestamp", "MMM d HH:mm:ss", "MMM dd HH:mm:ss" ]
		}
		mutate {
			exclude_tags => "_grokparsefailure"
			replace => [ "@source_host", "%{syslog_hostname}" ]
			replace => [ "@message", "%{syslog_message}" ]
		}
		mutate {
			remove => [ "syslog_hostname", "syslog_message", "syslog_timestamp", "received_at", "received_from" ]
		}
	}
	if "_grokparsefailure" in [tags] {
		if "syslog" in [tags] {
			grok {
				break_on_match => false
				match => [
				"message", "${GREEDYDATA:message-syslog}"
				]
			}
		}
	}
}
filter {
	if "VMware" in [tags] {
		grok {
			break_on_match => false
			match => [
				"message", "<%{POSINT:syslog_pri}>%{TIMESTAMP_ISO8601:@timestamp} %{SYSLOGHOST:hostname} %{SYSLOGPROG:message_program}: (?<message-body>(?<message_system_info>(?:\[%{DATA:message_thread_id} %{DATA:syslog_level} \'%{DATA:message_service}\'\ ?%{DATA:message_opID}])) \[%{DATA:message_service_info}]\ (?<message-syslog>(%{GREEDYDATA})))",
				"message", "<%{POSINT:syslog_pri}>%{TIMESTAMP_ISO8601:@timestamp} %{SYSLOGHOST:hostname} %{SYSLOGPROG:message_program}: (?<message-body>(?<message_system_info>(?:\[%{DATA:message_thread_id} %{DATA:syslog_level} \'%{DATA:message_service}\'\ ?%{DATA:message_opID}])) (?<message-syslog>(%{GREEDYDATA})))",
				"message", "<%{POSINT:syslog_pri}>%{TIMESTAMP_ISO8601:@timestamp} %{SYSLOGHOST:hostname} %{SYSLOGPROG:message_program}: %{GREEDYDATA:message-syslog}"
			]
		}
	}
	if "_grokparsefailure" in [tags] {
		if "VMware" in [tags] {
			grok {
				break_on_match => false
				match => [
					"message", "<%{POSINT:syslog_pri}>%{DATA:message_system_info}, (?<message-body>(%{SYSLOGHOST:hostname} %{SYSLOGPROG:message_program}: %{GREEDYDATA:message-syslog}))",
					"message", "${GREEDYDATA:message-syslog}"
				]
			}
		}
	}
}
output {
        elasticsearch_http {
                host => "127.0.0.1"
                flush_size => 1
                manage_template => false
        }
}
EOF

# Restart rsyslog service
service rsyslog restart

# Restart logstash service
service logstash restart

# Install and configure Kibana3 frontend
if [ ! -d "/var/www/html" ]; then
	mkdir /var/www/html
fi
cd /var/www/html
wget https://download.elasticsearch.org/kibana/kibana/kibana-3.0.1.tar.gz
tar zxvf kibana-*
rm kibana-*.tar.gz
mv kibana-* kibana
ln -s /var/www/html/kibana /var/www/kibana

# All Done
echo "Installation has completed!!"
echo -e "Connect to ${red}http://$yourfqdn/kibana${NC} or ${red}http://$IPADDY/kibana${NC}"
echo "${yellow}EveryThingShouldBeVirtual.com${NC}"
echo "${yellow}@mrlesmithjr${NC}"
echo "${yellow}Enjoy!!!${NC}"