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
./configure --enable-curl --enable-curl_json --enable-curl_xml --enable-dbi --enable-python --enable-mysql --enable-smtp --enable-ping
make all install

# All Done
echo "Installation has completed!!"
echo "${yellow}EveryThingShouldBeVirtual.com${NC}"
echo "${yellow}@mrlesmithjr${NC}"
echo "${yellow}Enjoy!!!${NC}"
