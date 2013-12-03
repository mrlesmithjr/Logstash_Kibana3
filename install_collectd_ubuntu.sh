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
apt-get install --yes flex bison libperl-dev python-dev libdbi-dev libyajl-dev libxml2-dev libmysqlclient-dev iptables-dev git make build-essential automake libtool pkg-config libgcrypt11-dev curl libesmtp-dev liboping-dev libpcap0.8-dev libcurl4-gnutls-dev librrd-dev libsensors4-dev libsnmp-dev chkconfig

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
ln -s /usr/lib/insserv/insserv /sbin/insserv
tee -a /etc/init.d/collectd <<EOF
#! /bin/bash
#
# collectd - start and stop the statistics collection daemon
# http://collectd.org/
#
# Copyright (C) 2005-2006 Florian Forster
# Copyright (C) 2006-2009 Sebastian Harl
#

### BEGIN INIT INFO
# Provides: collectd
# Required-Start: $local_fs $remote_fs
# Required-Stop: $local_fs $remote_fs
# Should-Start: $network $named $syslog $time
# Should-Stop: $network $named $syslog
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: start the statistics collection daemon
### END INIT INFO

set -e

PATH=/sbin:/bin:/usr/sbin:/usr/bin

DISABLE=0

DESC="statistics collection and monitoring daemon"
NAME=collectd
DAEMON=/usr/sbin/collectd

CONFIGFILE=/etc/collectd.conf
PIDFILE=/var/run/collectd.pid

USE_COLLECTDMON=1
COLLECTDMON_DAEMON=/usr/sbin/collectdmon
COLLECTDMON_PIDFILE=/var/run/collectdmon.pid

MAXWAIT=30

# Gracefully exit if the package has been removed.
test -x $DAEMON || exit 0

if [ -r /etc/default/$NAME ]; then
. /etc/default/$NAME
fi

if test "$DISABLE" != 0 -a "$1" == "start"; then
echo "$NAME has been disabled - see /etc/default/$NAME."
exit 0
fi

if test ! -e "$CONFIGFILE" -a "$1" == "start"; then
echo "Not starting $NAME - no configuration ($CONFIGFILE) found."
exit 0
fi

if test "$ENABLE_COREFILES" == 1; then
ulimit -c unlimited
fi

if test "$USE_COLLECTDMON" == 1; then
_PIDFILE="$COLLECTDMON_PIDFILE"
else
_PIDFILE="$PIDFILE"
fi

check_config() {
if ! $DAEMON -t -C "$CONFIGFILE"; then
if test -n "$1"; then
echo "$1" >&2
fi
exit 1
fi
}

d_start() {
if test "$DISABLE" != 0; then
# we get here during restart
echo -n " - disabled by /etc/default/$NAME"
return 0
fi

if test ! -e "$CONFIGFILE"; then
# we get here during restart
echo -n " - no configuration ($CONFIGFILE) found."
return 0
fi

check_config

if test "$USE_COLLECTDMON" == 1; then
start-stop-daemon --start --quiet --oknodo --pidfile "$_PIDFILE" \
--exec $COLLECTDMON_DAEMON -- -P "$_PIDFILE" -- -C "$CONFIGFILE"
else
start-stop-daemon --start --quiet --oknodo --pidfile "$_PIDFILE" \
--exec $DAEMON -- -C "$CONFIGFILE" -P "$_PIDFILE"
fi
}

still_running_warning="
WARNING: $NAME might still be running.
In large setups it might take some time to write all pending data to
the disk. You can adjust the waiting time in /etc/default/collectd."

d_stop() {
PID=$( cat "$_PIDFILE" 2> /dev/null ) || true

start-stop-daemon --stop --quiet --oknodo --pidfile "$_PIDFILE"

sleep 1
if test -n "$PID" && kill -0 $PID 2> /dev/null; then
i=0
while kill -0 $PID 2> /dev/null; do
i=$(( $i + 2 ))
echo -n " ."

if test $i -gt $MAXWAIT; then
echo "$still_running_warning" >&2
return 1
fi

sleep 2
done
return 0
fi
}

d_status() {
PID=$( cat "$_PIDFILE" 2> /dev/null ) || true

if test -n "$PID" && kill -0 $PID 2> /dev/null; then
echo "collectd ($PID) is running."
exit 0
else
PID=$( pidof collectd ) || true

if test -n "$PID"; then
echo "collectd ($PID) is running."
exit 0
else
echo "collectd is stopped."
fi
fi
exit 1
}

case "$1" in
start)
echo -n "Starting $DESC: $NAME"
d_start
echo "."
;;
stop)
echo -n "Stopping $DESC: $NAME"
d_stop
echo "."
;;
status)
d_status
;;
restart|force-reload)
echo -n "Restarting $DESC: $NAME"
check_config "Not restarting collectd."
d_stop
sleep 1
d_start
echo "."
;;
*)
echo "Usage: $0 {start|stop|restart|force-reload|status}" >&2
exit 1
;;
esac

exit 0

# vim: syntax=sh noexpandtab sw=4 ts=4 :
EOF

# Configure collectd to start on boot
chmod 755 /etc/init.d/collectd
chown root:root /etc/init.d/collectd
chkconfig --add collectd
/etc/init.d/collectd start
chkconfig collectd on

# Accept user input for Graphite Carbon Server
echo -n "Enter the IP/Hostname of your Graphite Carbon Server: "
read carbonserver

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
/etc/init.d/collectd restart

# All Done
echo "Installation has completed!!"
echo "${yellow}EveryThingShouldBeVirtual.com${NC}"
echo "${yellow}@mrlesmithjr${NC}"
echo "${yellow}Enjoy!!!${NC}"
