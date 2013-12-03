Logstash and Kibana3 Auto Install script
----------------------------------------

This script is for doing an automated install of logstash and the kibana3 front end. It will also setup some tagging and cleanup for VMware ESXi hosts.

Install instructions.
git clone https://github.com/mrlesmithjr/Logstash_Kibana3
chmod +x ./Logstash_Kibana3/install_logstash_kibana_ubuntu.sh
sudo ./Logstash_Kibana3/install_logstash_kibana_ubuntu.sh

Configure (r)syslog clients to send on udp/514
Configure ESX(i) clients to send on tcp/514

**Note** Kibana2 is also installed into /opt/kibana2 but is not running so you can start it up if you want to use Kibana2 instead or together with Kibana3.

Graphite
--------
You can also install Graphite Carbon on the same server as logstash/kibana3 or on a totally separate server.

Install instructions.
chmod +x ./Logstash_Kibana3/install_graphite_ubuntu.sh
sudo ./Logstash_Kibana3/install_graphite_ubuntu.sh

Graphite will be running on tcp/8080 after the installer completes.
use your browser of choice and connect to http://IP|hostname:8080

Collectd
--------
You can use the collectd installer to install on any server that you want to send metrics to your Graphite Carbon instance. The installer will prompt for your Graphite Carbon server (use IP or hostname). It is also assumed that Graphite Carbon is listening on the default of tcp/2003.

Install instructions.
chmod +x ./Logstash_Kibana3/install_collectd_ubuntu.sh
sudo ./Logstash_Kibana3/install_collectd_ubuntu.sh

Visit Me
--------
http://everythingshouldbevirtual.com
@mrlesmithjr
