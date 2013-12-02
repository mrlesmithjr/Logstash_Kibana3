apt-key adv --recv-keys --keyserver keyserver.ubuntu.com AEF0CF8E
gpg --export --armor AEF0CF8E | sudo apt-key add -

echo "# Rsyslog updated repo
# Adiscon repository
deb http://ubuntu.adiscon.com/v7-stable precise/
deb-src http://ubuntu.adiscon.com/v7-stable precise/" | tee -a /etc/apt/sources.list

apt-get update && apt-get upgrade
apt-get -y install rsyslog rsyslog-mmjsonparse

sed -i -e 's|#$ModLoad immark|$ModLoad immark|' /etc/rsyslog.conf
sed -i -e 's|#$ModLoad imudp|$ModLoad imudp|' /etc/rsyslog.conf
sed -i -e 's|#$UDPServerRun 514|$UDPServerRun 514|' /etc/rsyslog.conf
sed -i -e 's|*.*;auth,authpriv.none|#*.*;auth,authpriv.none|' /etc/rsyslog.d/50-default.conf

(
cat <<'EOF'
# Adding JSON support
$ModLoad mmjsonparse
*.* :mmjsonparse:
EOF
)| tee -a /etc/rsyslog.conf

(
cat <<'EOF'
$template ls_json,"{%timestamp:::date-rfc3339,jsonf:@timestamp%,\"@message\":\"%msg:::json%\",\"@fields\":{%fromhost:::jsonf:host%,%syslogfacility-text:::jsonf:syslog_facility%,%syslogfacility:::jsonf:syslog_facility_code%,%syslogseverity-text:::jsonf:syslog_severity%,%syslogseverity:::jsonf:syslog_severity_code%,%app-name:::jsonf:program%,%procid:::jsonf:pid%}}"
*.* @localhost:10514;ls_json
EOF
) | tee /etc/rsyslog.d/60-rsyslog-logstash.conf

mv /etc/logstash/logstash.conf /etc/logstash/logstash.conf.orig
tee -a /etc/logstash/logstash.conf <<EOF
input {
  udp {
    type => "syslog"
    port => "10514"
    buffer_size => 8192
    format => "json_event"
  }
}
output {
  elasticsearch_http {
  host => "127.0.0.1"
  flush_size => 1
  }
}
EOF

service logstash stop
service rsyslog restart
service logstash start
