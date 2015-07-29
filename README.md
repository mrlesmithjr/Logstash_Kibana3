Logstash and Kibana3 Auto Install script
----------------------------------------

This script is for doing an automated install of logstash and the kibana3 front end. It will also setup some tagging and cleanup for VMware ESXi hosts.

## Install instructions.

    git clone https://github.com/mrlesmithjr/Logstash_Kibana3

### For Logstash 1.3.x

    chmod +x ./Logstash_Kibana3/install_logstash_kibana_ubuntu.sh
    sudo ./Logstash_Kibana3/install_logstash_kibana_ubuntu.sh

### For Logstash 1.4.x

    chmod +x ./Logstash_Kibana3/install_logstash_1.4_kibana_ubuntu.sh
    sudo ./Logstash_Kibana3/install_logstash_1.4_kibana_ubuntu.sh

## Setup syslog for devices as follows.

### Port List

* TCP/514 Syslog (Devices supporting TCP)
* UDP/514 Syslog (Devices that do not support TCP - Only use if absolutely necessary)
* TCP/1514 VMware ESXi
* TCP/1515 VMware vCenter (Windows install or appliance) (For Windows install use NXLog from below in device setup) (For appliance reference device setup below)
* TCP/3515 Windows Eventlog (Use NXLog from below in device setup)
* TCP/3525 Windows IIS Logs (Use NXLog from below in device setup)

Visit Me
--------
http://everythingshouldbevirtual.com
@mrlesmithjr
