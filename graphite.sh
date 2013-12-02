#! /bin/bash

#Provided by @mrlesmithjr
#EveryThingShouldBeVirtual.com

set -e

# Setting colors for output
red="$(tput setaf 1)"
yellow="$(tput bold ; tput setaf 3)"
NC="$(tput sgr0)"
echo "${yellow}Capturing your FQDN${NC}"
yourfqdn=$(hostname -f)
echo "${yellow}Detecting IP Address${NC}"
IPADDY="$(ifconfig | grep -A 1 'eth0' | tail -1 | cut -d ':' -f 2 | cut -d ' ' -f 1)"
echo "Detected IP Address is ${red}$IPADDY${NC}"


# Download Graphite, Carbon and Whisper
cd /opt
wget https://launchpad.net/graphite/0.9/0.9.10/+download/graphite-web-0.9.10.tar.gz
wget https://launchpad.net/graphite/0.9/0.9.10/+download/carbon-0.9.10.tar.gz
wget https://launchpad.net/graphite/0.9/0.9.10/+download/whisper-0.9.10.tar.gz
tar -zxvf graphite-web-0.9.10.tar.gz
tar -zxvf carbon-0.9.10.tar.gz
tar -zxvf whisper-0.9.10.tar.gz
rm graphite-web-0.9.10.tar.gz
rm carbon-0.9.10.tar.gz
rm whisper-0.9.10.tar.gz
mv graphite-web-0.9.10 graphite
mv whisper-0.9.10 whisper
mv carbon-0.9.10 carbon

# Install Dependencies
apt-get update
apt-get install --assume-yes apache2 apache2-mpm-worker apache2-utils apache2.2-bin apache2.2-common libapr1 libaprutil1 libaprutil1-dbd-sqlite3 build-essential python3.2 python-dev libpython3.2 python3-minimal libapache2-mod-wsgi libaprutil1-ldap memcached python-cairo-dev python-django python-ldap python-memcache python-pysqlite2 sqlite3 erlang-os-mon erlang-snmp rabbitmq-server bzr expect ssh libapache2-mod-python python-setuptools

# Install PIP Dependencies
easy_install django-tagging
easy_install zope.interface
easy_install twisted==12.2.0
easy_install daemonize

# Install Whisper
cd /opt/whisper
python setup.py install

# Install Carbon
cd /opt/carbon
python setup.py install
cd /opt/graphite/conf
cp carbon.conf.example carbon.conf

# create storage-schemas.conf
tee -a /opt/graphite/conf/storage-schemas.conf <<EOF
[everything_1min_13months]
priority = 100
pattern = .*
retentions = 1m:395d
EOF

# Configure Graphite (webapp)
cd /opt/graphite
python check-dependencies.py
python setup.py install

# Configure Apache to run Graphite on port 8080
cd /opt/graphite/examples
cp example-graphite-vhost.conf /etc/apache2/sites-available/graphite-vhost.conf
sed -i -e 's|*:80>|*:8080>|' /etc/apache2/sites-available/graphite-vhost.conf
cp /opt/graphite/conf/graphite.wsgi.example /opt/graphite/conf/graphite.wsgi
mkdir -p /etc/httpd/wsgi
sed -i -e "s|WSGISocketPrefix run/wsgi|WSGISocketPrefix /etc/httpd/wsgi|" /etc/apache2/sites-available/graphite-vhost.conf
a2ensite graphite-vhost.conf
echo NameVirtualHost *:8080| tee -a /etc/apache2/ports.conf
echo Listen 8080| tee -a /etc/apache2/ports.conf
service apache2 reload

# INITIAL DATABASE CREATION
cd /opt/graphite/webapp/graphite/
sudo python manage.py syncdb
# follow prompts to setup django admin user
chown -R www-data:www-data /opt/graphite/storage/
service apache2 restart
cd /opt/graphite/webapp/graphite
cp local_settings.py.example local_settings.py

# Start Carbon
#fix issue with demonize
#sed -i -e’s|from twisted.scripts._twistd_unix import daemonize|import daemonize|’ /opt/graphite/lib/carbon/util.py
cd /opt/graphite/
./bin/carbon-cache.py start

# All Done
echo "Installation has completed!!"
echo -e "Connect to ${red}http://$yourfqdn:8080{NC} or ${red}http://$IPADDY:8080{NC}"
echo "${yellow}EveryThingShouldBeVirtual.com${NC}"
echo "${yellow}@mrlesmithjr${NC}"
echo "${yellow}Enjoy!!!${NC}"
