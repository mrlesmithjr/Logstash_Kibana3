#! /bin/bash

#Provided by @mrlesmithjr
#EveryThingShouldBeVirtual.com

# This script will install collectd on a Ubuntu system

set -e

# Setting colors for output
red="$(tput setaf 1)"
yellow="$(tput bold ; tput setaf 3)"
NC="$(tput sgr0)"

# Install dependencies
apt-get install --yes flex bison libperl-dev python-dev libdbi-dev libyajl-dev libxml2-dev libmysqlclient-dev iptables-dev git make build-essential automake libtool pkg-config libgcrypt11-dev curl libesmtp-dev liboping-dev libpcap0.8-dev libcurl4-gnutls-dev librrd-dev libsensors4-dev libsnmp-dev

# Download, build and install collectd
cd /opt
wget http://collectd.org/files/collectd-5.4.0.tar.gz
tar zxvf collectd-5.4.0.tar.gz
rm collectd-5.4.0.tar.gz
mv collectd*/ collectd
#git clone https://github.com/collectd/collectd
cd collectd
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libdir=/usr/lib --mandir=/usr/share/man --enable-curl --enable-curl_json --enable-curl_xml --enable-dbi --enable-python --enable-mysql --enable-smtp --enable-ping
make all install

# Create /etc/init.d/collectd startup script
cd /tmp
wget https://github.com/collectd/collectd/blob/master/contrib/upstart.collectd.conf
cp /tmp/upstart.collectd.conf /etc/init/collectd.conf
touch /var/log/upstart/collectd.log
initctl reload-configuration

# Accept user input for Graphite Carbon Server
echo -n "Enter the IP/Hostname of your Graphite Carbon Server: "
read carbonserver

mv /etc/collectd.conf /etc/collectd.conf.orig
tee -a /etc/collectd.conf <<EOF
#
# Config file for collectd(1).
# Please read collectd.conf(5) for a list of options.
# http://collectd.org/
#
 
Hostname "$(hostname)"
 
Interval 10
ReadThreads 5
 
LoadPlugin syslog
LoadPlugin logfile
LoadPlugin cpu
LoadPlugin interface
LoadPlugin load
LoadPlugin memory
LoadPlugin write_graphite
 
<Plugin write_graphite>
<Carbon>
Host "$carbonserver"
Port "2003"
Prefix ""
Postfix ""
SeparateInstances true
</Carbon>
</Plugin>
EOF

# Restart collectd
sudo initctl stop collectd
sudo initctl start collectd

# All Done
echo "Installation has completed!!"
echo "${yellow}EveryThingShouldBeVirtual.com${NC}"
echo "${yellow}@mrlesmithjr${NC}"
echo "${yellow}Enjoy!!!${NC}"
