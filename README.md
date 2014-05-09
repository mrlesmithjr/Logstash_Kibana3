Logstash and Kibana3 Auto Install script
----------------------------------------

This script is for doing an automated install of logstash and the kibana3 front end. It will also setup some tagging and cleanup for VMware ESXi hosts.

Install instructions.
git clone https://github.com/mrlesmithjr/Logstash_Kibana3

For Logstash 1.3.x
chmod +x ./Logstash_Kibana3/install_logstash_kibana_ubuntu.sh
sudo ./Logstash_Kibana3/install_logstash_kibana_ubuntu.sh

For Logstash 1.4.x
chmod +x ./Logstash_Kibana3/install_logstash_1.4_kibana_ubuntu.sh
sudo ./Logstash_Kibana3/install_logstash_1.4_kibana_ubuntu.sh

Configure (r)syslog clients to send on udp/514
Configure ESX(i) clients to send on tcp/514

Visit Me
--------
http://everythingshouldbevirtual.com
@mrlesmithjr
