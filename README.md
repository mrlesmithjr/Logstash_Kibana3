Logstash and Kibana3 Auto Install script
----------------------------------------

This script is for doing an automated install of logstash and the kibana3 front end. It will also setup some tagging and cleanup for VMware ESXi hosts.

Install instructions.
```bash
git clone https://github.com/mrlesmithjr/Logstash_Kibana3
chmod +x ./Logstash_Kibana3/install_logstash_kibana_ubuntu.sh
sudo ./Logstash_Kibana3/install_logstash_kibana_ubuntu.sh
```

Configure (r)syslog clients to send on udp/514
Configure ESX(i) clients to send on tcp/514

**Note** Kibana2 is also installed into /opt/kibana2 but is not running so you can start it up if you want to use Kibana2 instead or together with Kibana3.

Visit Me
--------
http://everythingshouldbevirtual.com
@mrlesmithjr
