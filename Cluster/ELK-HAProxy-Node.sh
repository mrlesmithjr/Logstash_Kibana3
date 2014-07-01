#!/bin/bash

#Provided by @mrlesmithjr
#EveryThingShouldBeVirtual.com

# This script will configure rsyslog to listen on UDP/514 and sort out some types of devices that do not support sending syslog to a TCP port.
# Logstash will send to the e elasticsearch logstash-cluster using redis
# Install this script on your frontend HAProxy Nodes. Because all devices will point to the VIP of HAProxy only the active node will receive syslog messages
# This will also support HAProxy cluster failover

set -e

# Setup logging
# Logs stderr and stdout to separate files.
exec 2> >(tee "./ELK-HAProxy-Node.err")
exec > >(tee "./ELK-HAProxy-Node.log")

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

# Allow VIPS to come up on both nodes
echo "net.ipv4.ip_nonlocal_bind=1" >> /etc/sysctl.conf

# Install Pre-Reqs
apt-get install -y --force-yes git curl nginx software-properties-common keepalived haproxy

# Remove nginx default site
rm /etc/nginx/sites-enabled/default
service nginx restart

# Install Oracle Java 7 **NOT Used - Installing openjdk-7-jre above
 echo "Installing Oracle Java 7"
 add-apt-repository -y ppa:webupd8team/java
 apt-get -qq update
 echo oracle-java7-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections
 apt-get install -y oracle-java7-installer oracle-java7-set-default

# Collect information for VIP (IP|HOSTNAME) To inject into script
echo "This following info is required to setup the KeepAliveD Priorities"
echo "If this is your first haproxy node being setup enter ${red}101${NC}"
echo "If this is your second haproxy node being setup enter ${red}100${NC}"
echo -n "Enter the correct number from above for the HAProxy node: "
read haproxynodeid
echo "Enter your HAProxy VIP IP address to use for setup"
echo "example 10.0.101.60"
echo -n "Enter HAProxy VIP: "
read haproxyvip
echo "You entered ${red}$haproxyvip%{NC}"
echo "Enter your HAProxy VIP hostname to use for setup"
echo "example logstash"
echo -n "Enter HAProxy VIP hostname: "
read haproxyhostname
echo "You entered ${red}$haproxyhostname${NC}"
echo "Enter your elk-broker nodes hostnames below"
echo "example elk-broker-1"
echo "example elk-broker-2"
echo -n "Enter elk broker node #1: "
read elkbroker1
echo -n "Enter elk broker node #2: "
read elkbroker2
echo "Enter your elk processor nodes hostnames"
echo "example elk-processor-1"
echo "example elk-processor-2"
echo -n "Enter elk processor node #1: "
read elkprocessor1
echo -n "Enter elk processor node #2: "
read elkprocessor2
echo "You entered ${red}$elkbroker1${NC} and ${red}$elkbroker2${NC}"
echo "Enter your ES (Elasticsearch) Master/Data nodes hostnames"
echo "example elk-es-1"
echo "example elk-es-2"
echo -n "Enter ES node #1: "
read esnode1
echo -n "Enter ES node #2: "
read esnode2

# Create /etc/keepalived/keepalived.conf
tee -a /etc/keepalived/keepalived.conf <<EOF
vrrp_script chk_haproxy {
   script "killall -0 haproxy"   # verify the pid existance
   interval 2                    # check every 2 seconds
   weight 2                      # add 2 points of prio if OK
}

vrrp_instance VI_1 {
   interface eth0                # interface to monitor
   state MASTER
   virtual_router_id 51          # Assign one ID for this route
   priority $haproxynodeid                  # 101 on master, 100 on backup (Make sure to change this on HAPROXY node2)
   virtual_ipaddress {
        $haproxyvip            # the virtual IP's
}
   track_script {
       chk_haproxy
   }
}
EOF

# Start KeepAliveD service
service keepalived start

# backup current /etc/haproxy/haproxy.cfg
mv /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.orig

# create new /etc/haproxy/haproxy.cfg file
tee -a /etc/haproxy/haproxy.cfg <<EOF
global
#        log $haproxyhostname    local0 #Change logstash to your naming
        log /dev/log    local0
        log /dev/log    local1 notice
        log-send-hostname
        chroot /var/lib/haproxy
        user haproxy
        group haproxy
        daemon
        maxconn 4000

defaults
        log     global
        mode    http
        option  httplog
        option  dontlognull
        option redispatch
        retries 3
        timeout client 35s
        timeout server 60s
        timeout connect 5s
        timeout http-keep-alive 10s
#        contimeout 5000
#        clitimeout 50000
#        srvtimeout 50000
        errorfile 400 /etc/haproxy/errors/400.http
        errorfile 403 /etc/haproxy/errors/403.http
        errorfile 408 /etc/haproxy/errors/408.http
        errorfile 500 /etc/haproxy/errors/500.http
        errorfile 502 /etc/haproxy/errors/502.http
        errorfile 503 /etc/haproxy/errors/503.http
        errorfile 504 /etc/haproxy/errors/504.http

listen stats :9090
        balance
        mode http
        stats enable
        stats auth admin:admin

listen logstash-syslog-TCP-514      $haproxyvip:514
        mode tcp
        option tcpka
        option tcplog
        #balance leastconn - The server with the lowest number of connections receives the connection
        #balance roundrobin - Each server is used in turns, according to their weights.
        #balance source - Source IP hashed and divided by total weight of servers designates which server will receive the request
        balance roundrobin
        server $elkbroker1 $elkbroker1:514 check
        server $elkbroker2 $elkbroker2:514 check

listen logstash-VMware-TCP-1514  $haproxyvip:1514
        mode tcp
        option tcpka
        option tcplog
        #balance leastconn - The server with the lowest number of connections receives the connection
        #balance roundrobin - Each server is used in turns, according to their weights.
        #balance source - Source IP hashed and divided by total weight of servers designates which server will receive the request
        balance roundrobin
        server $elkbroker1 $elkbroker1:1514 check
        server $elkbroker2 $elkbroker2:1514 check

listen logstash-vCenter-TCP-1515  $haproxyvip:1515
        mode tcp
        option tcpka
        option tcplog
        #balance leastconn - The server with the lowest number of connections receives the connection
        #balance roundrobin - Each server is used in turns, according to their weights.
        #balance source - Source IP hashed and divided by total weight of servers designates which server will receive the request
        balance roundrobin
        server $elkbroker1 $elkbroker1:1515 check
        server $elkbroker2 $elkbroker2:1515 check

listen logstash-Netscaler-TCP-1517  $haproxyvip:1517
        mode tcp
        option tcpka
        option tcplog
        #balance leastconn - The server with the lowest number of connections receives the connection
        #balance roundrobin - Each server is used in turns, according to their weights.
        #balance source - Source IP hashed and divided by total weight of servers designates which server will receive the request
        balance roundrobin
        server $elkbroker1 $elkbroker1:1517 check
        server $elkbroker2 $elkbroker2:1517 check

listen logstash-eventlog-TCP-3515  $haproxyvip:3515
        mode tcp
        option tcpka
        option tcplog
        #balance leastconn - The server with the lowest number of connections receives the connection
        #balance roundrobin - Each server is used in turns, according to their weights.
        #balance source - Source IP hashed and divided by total weight of servers designates which server will receive the request
        balance roundrobin
        server $elkbroker1 $elkbroker1:3515 check
        server $elkbroker2 $elkbroker2:3515 check

listen logstash-iis-TCP-3525  $haproxyvip:3525
        mode tcp
        option tcpka
        option tcplog
        #balance leastconn - The server with the lowest number of connections receives the connection
        #balance roundrobin - Each server is used in turns, according to their weights.
        #balance source - Source IP hashed and divided by total weight of servers designates which server will receive the request
        balance roundrobin
        server $elkbroker1 $elkbroker1:3525 check
        server $elkbroker2 $elkbroker2:3525 check

listen logstash-redis-TCP-6379  $haproxyvip:6379
        mode tcp
        option tcpka
        option tcplog
        #balance leastconn - The server with the lowest number of connections receives the connection
        #balance roundrobin - Each server is used in turns, according to their weights.
        #balance source - Source IP hashed and divided by total weight of servers designates which server will receive the request
        balance roundrobin
        server $elkbroker1 $elkbroker1:6379 check
        server $elkbroker2 $elkbroker2:6379 check

listen elasticsearch-TCP-9200 $haproxyvip:9200
        mode tcp
        option tcpka
        option tcplog
        #balance leastconn - The server with the lowest number of connections receives the connection
        #balance roundrobin - Each server is used in turns, according to their weights.
        #balance source - Source IP hashed and divided by total weight of servers designates which server will receive the request
        balance roundrobin
        server $elkprocessor1 $elkprocessor1:9200 check
        server $elkprocessor2 $elkprocessor2:9200 check

listen elasticsearch-TCP-9300 $haproxyvip:9300
        mode tcp
        option tcpka
        option tcplog
        #balance leastconn - The server with the lowest number of connections receives the connection
        #balance roundrobin - Each server is used in turns, according to their weights.
        #balance source - Source IP hashed and divided by total weight of servers designates which server will receive the request
        balance roundrobin
        server $esnode1 $esnode1:9300 check
        server $esnode2 $esnode2:9300 check

listen kibana-http $haproxyvip:80
        mode http
        stats enable
        stats auth admin:password # Change this to your own username and password!
        #balance leastconn - The server with the lowest number of connections receives the connection
        #balance roundrobin - Each server is used in turns, according to their weights.
        #balance source - Source IP hashed and divided by total weight of servers designates which server will receive the request
        balance source
        option httpclose
        option forwardfor except $IPADDY # 10.0.101.61 # Change this to 10.0.101.62 (Or IP of second node) when setting up second node
        cookie JSESSIONID prefix indirect nocache
        server $elkprocessor1 $elkprocessor1:80 check cookie L1
        server $elkprocessor2 $elkprocessor2:80 check cookie L2

#listen kibana-https $haproxyvip:8443
#        mode http
#        stats enable
#        stats auth admin:password # Change this to your own username and password!
#        #balance leastconn - The server with the lowest number of connections receives the connection
#        #balance roundrobin - Each server is used in turns, according to their weights.
#        #balance source - Source IP hashed and divided by total weight of servers designates which server will receive the request
#        balance source
#        #option httpchk
#        option httpclose
#        option forwardfor except $IPADDY #10.0.101.61 # Change this to 10.0.101.62 (Or IP of second node) when setting up second node
#        cookie JSESSIONID prefix indirect nocache
#        server $elkprocessor1 $elkprocessor1:8080 check cookie L1
#        server $elkprocessor2 $elkprocessor2:8080 check cookie L2
EOF

# Enable HAProxy to start
sed -i -e 's|ENABLED=0|ENABLED=1|' /etc/default/haproxy

# Install Logstash
cd /opt
#wget https://download.elasticsearch.org/logstash/logstash/logstash-1.4.1.tar.gz
wget https://download.elasticsearch.org/logstash/logstash/logstash-1.4.2.tar.gz
tar zxvf logstash-*.tar.gz
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

# Setting up rsyslog to receive remote syslog on UDP/514 and then send back out to TCP/514 to the logstash cluster
echo "Setting up rsyslog to receive remote syslog on UDP/514"
sed -i -e 's|#$ModLoad imudp|$ModLoad imudp|' /etc/rsyslog.conf
sed -i -e 's|#$UDPServerRun 514|$UDPServerRun 514|' /etc/rsyslog.conf
echo '*.* @@'$logstashinfo'' | tee -a  /etc/rsyslog.d/50-default.conf
service rsyslog restart

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
output {
        redis {
                host => $haproxyhostname
                data_type => "list"
                key => "logstash"
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
        "actconn": { "type": "long", "index": "not_analyzed" },
        "backend_queue": { "type": "long", "index": "not_analyzed" },
        "beconn": { "type": "long", "index": "not_analyzed" },
        "bytes": { "type": "long", "index": "not_analyzed" },
        "bytes_read": { "type": "long", "index": "not_analyzed" },
        "datastore_latency_from": { "type": "long", "index": "not_analyzed" },
        "datastore_latency_to": { "type": "long", "index": "not_analyzed" },
        "feconn": { "type": "long", "index": "not_analyzed" },
        "response_time": { "type": "long", "index": "not_analyzed" },
        "retries": { "type": "long", "index": "not_analyzed" },
        "srv_queue": { "type": "long", "index": "not_analyzed" },
        "srvconn": { "type": "long", "index": "not_analyzed" },
        "time_backend_connect": { "type": "long", "index": "not_analyzed" },
        "time_backend_response": { "type": "long", "index": "not_analyzed" },
        "time_duration": { "type": "long", "index": "not_analyzed" },
        "time_queue": { "type": "long", "index": "not_analyzed" },
        "time_request": { "type": "long", "index": "not_analyzed" }
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

# Start Haproxy
service haproxy restart

# All Done
echo "Installation has completed!!"
echo "Now continue on and setup your ELK-Processor nodes"
echo "${yellow}EveryThingShouldBeVirtual.com${NC}"
echo "${yellow}@mrlesmithjr${NC}"
echo "${yellow}Enjoy!!!${NC}"
