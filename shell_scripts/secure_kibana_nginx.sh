#!/bin/bash

#Provided by @mrlesmithjr
#EveryThingShouldBeVirtual.com

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

# Install nginx and apache2 utils for htpasswd
apt-get -y install nginx apache2-utils

chown -R www-data:www-data /usr/share/nginx/html

# Capture username/password to use
echo -n "Enter read-only username to use for kibana login and press enter: "
read kibanarouser
htpasswd -c /etc/nginx/conf.d/kibana.htpasswd $kibanarouser
echo -n "Enter admin username to use for kibana login and press enter: "
read kibanaadminuser
htpasswd /etc/nginx/conf.d/kibana.htpasswd $kibanaadminuser
echo "Enter the same password for above admin user again to grant write access"
htpasswd -c /etc/nginx/conf.d/kibana-write.htpasswd $kibanaadminuser

# Generate SSL Key
mkdir /etc/nginx/ssl
cd /etc/nginx/ssl
openssl genrsa -des3 -out server.key 1024
openssl req -new -key server.key -out server.csr
cp server.key server.key.org
openssl rsa -in server.key.org -out server.key
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

# Capture elasticsearch hostname/cluster to use
echo "When entering elasticsearch hostname or clustername below follow the methods below.."
echo "If running elasticsearch on this host....enter localhost or 127.0.0.1 "
echo "If running elasticsearch on a separate host...enter hostname or IP of host "
echo "If running elasticsearch as a highly available cluster behind a Load Balancer (Proxy)"
echo "Enter VIP hostname or VIP IP...i.e. (logstash or 192.168.1.200) "
echo -n "Enter elasticsearch info (as directed above) and press enter: "
read esinfo

# Create nginx-logstash website for nginx
tee -a /etc/nginx/sites-available/nginx-logstash <<EOF
# Nginx proxy for Elasticsearch + Kibana
#
# In this setup, we are password protecting the saving of dashboards. You may
# wish to extend the password protection to all paths.
#
# Even though these paths are being called as the result of an ajax request, the
# browser will prompt for a username/password on the first request
#
# If you use this, you'll want to point config.js at http://FQDN:80/ instead of
# http://FQDN:9200
#
server {
    listen      80;
    return 301 https://$IPADDY;
}
server {
  listen                *:443 ;
 
  ssl on;
  ssl_certificate /etc/nginx/ssl/server.crt;
  ssl_certificate_key /etc/nginx/ssl/server.key;
 
  server_name           $yourfqdn;
  access_log            /var/log/nginx/kibana.access.log;
 
  location / {
    root  /usr/share/nginx/html/kibana;
    index  index.html  index.htm;
 
    auth_basic "Restricted";
    auth_basic_user_file /etc/nginx/conf.d/kibana.htpasswd;
 
  }
 
  location ~ ^/_aliases$ {
    proxy_pass http://$esinfo:9200;
    proxy_read_timeout 90;
  }
  location ~ ^/.*/_aliases$ {
    proxy_pass http://$esinfo:9200;
    proxy_read_timeout 90;
  }
  location ~ ^/_nodes$ {
    proxy_pass http://$esinfo:9200;
    proxy_read_timeout 90;
  }
  location ~ ^/.*/_search$ {
    proxy_pass http://$esinfo:9200;
    proxy_read_timeout 90;
  }
  location ~ ^/.*/_mapping$ {
    proxy_pass http://$esinfo:9200;
    proxy_read_timeout 90;
  }
 
  # Password protected end points
  location ~ ^/kibana-int/dashboard/.*$ {
    proxy_pass http://$esinfo:9200;
    proxy_read_timeout 90;
    limit_except GET {
      proxy_pass http://$esinfo:9200;
      auth_basic "Restricted";
      auth_basic_user_file /etc/nginx/conf.d/kibana-write.htpasswd;
    }
  }
  location ~ ^/kibana-int/temp.*$ {
    proxy_pass http://$esinfo:9200;
    proxy_read_timeout 90;
    limit_except GET {
      proxy_pass http://$esinfo:9200;
      auth_basic "Restricted";
      auth_basic_user_file /etc/nginx/conf.d/kibana-write.htpasswd;
    }
  }
}
EOF

# Change nginx default website to new logstash-nginx
rm /etc/nginx/sites-enabled/default
ln -s /etc/nginx/sites-available/nginx-logstash /etc/nginx/sites-enabled/nginx-logstash

# Restart nginx
service nginx restart
