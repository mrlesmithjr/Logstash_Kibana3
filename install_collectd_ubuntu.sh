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
(
cat <<'EOF'
description "start/stop/control collectd"
# http://collectd.org/
# Upstart is the replacement init system used in Debian, Ubuntu,
# and in Fedora. Refer to http://upstart.ubuntu.com/cookbook/
#
# Normally this file will live as `/etc/init/collectd.conf`

usage "initctl <start|stop> collectd"
author "Dave Cottlehuber <dch@jsonified.com>"
version "1.1"

# There are a number of alternative start sequences however
# most of those do not work on all Ubuntu flavours and releases.
start on started networking and filesystem
stop on runlevel [!2345]

# collectd itself will run with reduced privileges, but not
# all plugins will. Test and edit as required.
# An alternative configuration is as a user script in ~/.init/ however
# these cannot be started at boot time by the system without
# arcane trickery. Also a root user will not see these tasks/jobs
# by default. set*id is a reasonable and secure compromise.
#setuid nobody
#setgid nobody

# Other parameters such as the path to the configuration file
# will have been compiled into the binary. These are trivially
# added as environment variables below, and then into both
# `pre-start` command check before collectd runs, and subsequent
# `exec` command parameters below. Remember that upstart runs all
# shell commands via `sh -e`.
env DAEMON=/usr/sbin/collectd

# Tell upstart to watch for forking when tracking the pid for us.
expect fork

# prevent thrashing - 10 restarts in 5 seconds
respawn
respawn limit 10 5

# Make a log available in /var/log/upstart/collectd.log
console log

# The daemon will not start if the configuration is invalid.
pre-start exec $DAEMON -t
# Let's Fork!
exec $DAEMON
EOF
) | tee -a /etc/init/collectd.conf
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
Protocol "tcp"
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
