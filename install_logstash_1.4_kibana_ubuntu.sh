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
#wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-0.90.11.deb
#dpkg -i elasticsearch-0.90.11.deb
wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.1.1.deb
dpkg -i elasticsearch-1.1.1.deb

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
echo "Now enter your PFSense Firewall hostname if you use it ${red}(DO NOT include your domain name)${NC}"
echo "If you do not use PFSense Firewall enter ${red}pfsense${NC}"
echo -n "Enter PFSense Hostname: "
read pfsensehostname
echo "You entered ${red}$pfsensehostname${NC}"

# Create Logstash configuration file
mkdir /etc/logstash
tee -a /etc/logstash/logstash.conf <<EOF
input {
  redis {
    host => "127.0.0.1"
    data_type => "list"
    key => "logstash"
  }
}
input {
	udp {
		type => "syslog"
		port => "514"
	}
}
input {
	tcp {
			type => "eventlog"
			port => 3515
			format => 'json'
	}
}
input {
	tcp {
			type => "iis"
			port => 3525
			format => 'json'
	}
}
filter {
	if [type] == "syslog" {
		dns {
			reverse => [ "host" ] action => "replace"
		}
		if [host] =~ /.*?($pfsensehostname).*?($yourdomainname)?/ {
			mutate {
				add_tag => [ "PFSense"]
			}
		}
		else if [host] =~ /.*?($esxinaming).*?($yourdomainname)?/ {
			mutate {
				add_tag => [ "VMware" ]
			}
		}
		else {
			mutate {
				add_tag => [ "syslog" ]
			}
		}
	}
	if [type] == "eventlog" {
		mutate {
			add_tag => [ "WindowsEventLog" ]
		}
	}
	if [type] == "iis" {
		mutate {
			add_tag => [ "IISLogs" ]
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
		mutate {
			replace => [ "@source_host", "%{hostname}" ]
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
			replace => [ "@message", "%{msg}" ]
		}
		mutate {
			replace => [ "@source_host", "%{host}" ]
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
}
filter {
	if "apache" in [type] {
		geoip {
			source => "clientip"
			target => "geoip"
			add_field => [ "[geoip][coordinates]", "%{[geoip][longitude]}" ]
			add_field => [ "[geoip][coordinates]", "%{[geoip][latitude]}"  ]
		}
		mutate {
			convert => [ "[geoip][coordinates]", "float" ]
		}
		mutate {
			replace => [ "@source_host", "%{host}" ]
		}
	}
}
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
			rename => [ "Severity", "eventlog_severity" ]
			rename => [ "SeverityValue", "eventlog_severity_code" ]
			rename => [ "Channel", "eventlog_channel" ]
			rename => [ "SourceName", "eventlog_program" ]
			rename => [ "SourceModuleName", "nxlog_input" ]
			rename => [ "Category", "eventlog_category" ]
			rename => [ "EventID", "eventlog_id" ]
			rename => [ "RecordNumber", "eventlog_record_number" ]
			rename => [ "ProcessID", "eventlog_pid" ]
		}
		mutate {
			remove => [ "SourceModuleType", "EventTimeWritten", "EventTime", "EventReceivedTime", "EventType" ]
		}
	}
}
filter {
	if [type] == "iis" {
		if [message] =~ "^#" {
				drop {}
		}
		grok {
			match => ["message", "%{DATESTAMP:eventtime} %{IP:host_ip} %{URIPROTO:method} %{URIPATH:path} (?:-|%{NOTSPACE:uri_query}sern) %{NUMBER:port} %{NOTSPACE:username} %{IP:client_ip} %{NOTSPACE:useragent} %{NUMBER:response} %{NUMBER:subresponse} %{NUMBER:scstatus} %{NUMBER:timetaken}"]
		} 
		date {
			 match => ["eventtime", "YY-MM-dd HH:mm:ss"]  
		}
	}
}
output {
	elasticsearch_http {
		host => "127.0.0.1"
		flush_size => 1
		manage_template => true
		template => "/opt/logstash/lib/logstash/outputs/elasticsearch/elasticsearch-template.json"
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
