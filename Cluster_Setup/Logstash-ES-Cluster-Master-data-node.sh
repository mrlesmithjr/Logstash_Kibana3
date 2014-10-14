#!/bin/bash

#Provided by @mrlesmithjr
#EveryThingShouldBeVirtual.com

# This script will setup an elasticsearch node as a dedicated data node only...no logstash instances

set -e
# Setup logging
# Logs stderr and stdout to separate files.
exec 2> >(tee "./Logstash_Kibana3/install_Logstash-ES-Cluster-Master-data-node.err")
exec > >(tee "./Logstash_Kibana3/install_Logstash-ES-Cluster-Master-data-node.log")

# Setting colors for output
red="$(tput setaf 1)"
yellow="$(tput bold ; tput setaf 3)"
NC="$(tput sgr0)"

# Capture your FQDN Domain Name and IP Address
echo "${yellow}Capturing your hostname${NC}"
yourhostname=$(hostname)
echo "${yellow}Capturing your domain name${NC}"
yourdomainname=$(dnsdomainname)
echo "${yellow}Capturing your FQDN${NC}"
yourfqdn=$(hostname -f)
echo "${yellow}Detecting IP Address${NC}"
IPADDY="$(ifconfig | grep -A 1 'eth0' | tail -1 | cut -d ':' -f 2 | cut -d ' ' -f 1)"
echo "Your hostname is currently ${red}$yourhostname${NC}"
echo "Your domain name is currently ${red}$yourdomainname${NC}"
echo "Your FQDN is currently ${red}$yourfqdn${NC}"
echo "Detected IP Address is ${red}$IPADDY${NC}"

# Disable CD Sources in /etc/apt/sources.list
echo "Disabling CD Sources and Updating Apt Packages and Installing Pre-Reqs"
sed -i -e 's|deb cdrom:|# deb cdrom:|' /etc/apt/sources.list
apt-get -qq update

############################### Logstash - Elasticsearch cluster Setup ##################################
# Install Pre-Reqs
apt-get install -y --force-yes git curl software-properties-common

# Install Oracle Java 7 **NOT Used - Installing openjdk-7-jre above
 echo "Installing Oracle Java 7"
 add-apt-repository -y ppa:webupd8team/java
 apt-get -qq update
 echo oracle-java7-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections
 apt-get install -y oracle-java7-installer oracle-java7-set-default

# Install Elasticsearch
cd /opt
#wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.1.1.deb
#dpkg -i elasticsearch-1.1.1.deb
#wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.2.1.deb
#dpkg -i elasticsearch-1.2.1.deb
wget https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.3.4.deb
dpkg -i elasticsearch-1.3.4.deb

# Configuring Elasticsearch
echo "### Below is added using install script ###" >> /etc/elasticsearch/elasticsearch.yml
echo "cluster.name: logstash-cluster" >> /etc/elasticsearch/elasticsearch.yml
echo "node.name: $yourhostname" >> /etc/elasticsearch/elasticsearch.yml
echo "node.master: true" >> /etc/elasticsearch/elasticsearch.yml
echo "node.data: true" >> /etc/elasticsearch/elasticsearch.yml
echo "index.number_of_shards: 5" >> /etc/elasticsearch/elasticsearch.yml
echo "index.number_of_replicas: 1" >> /etc/elasticsearch/elasticsearch.yml
echo "bootstrap.mlockall: true" >> /etc/elasticsearch/elasticsearch.yml
echo "##### Uncomment below instead of using multicast and update with your actual ES Master/Data nodenames #####" >> /etc/elasticsearch/elasticsearch.yml
echo '#discovery.zen.ping.unicast.hosts: ["es-1", "es-2"]' >> /etc/elasticsearch/elasticsearch.yml
echo "#discovery.zen.ping.multicast.enabled: false" >> /etc/elasticsearch/elasticsearch.yml
echo "#### Prevent split brain ES Cluster n/2+1 ####" >> /etc/elasticsearch/elasticsearch.yml
echo "#discovery.zen.minimum_master_nodes: 1" >> /etc/elasticsearch/elasticsearch.yml

# Making changes to /etc/security/limits.conf to allow more open files for elasticsearch
mv /etc/security/limits.conf /etc/security/limits.bak
grep -Ev "# End of file" /etc/security/limits.bak > /etc/security/limits.conf
echo "elasticsearch soft nofile 65536" >> /etc/security/limits.conf
echo "elasticsearch hard nofile 65536" >> /etc/security/limits.conf
echo "elasticsearch - memlock unlimited" >> /etc/security/limits.conf
echo "# End of file" >> /etc/security/limits.conf

# Modify elasticsearch service for ulimit -l unlimited to allow mlockall to work correctly
sed -i -e 's|^#ES_HEAP_SIZE=2g|ES_HEAP_SIZE=2g|' /etc/init.d/elasticsearch
sed -i -e 's|^#MAX_LOCKED_MEMORY=|MAX_LOCKED_MEMORY=unlimited|' /etc/init.d/elasticsearch

# Set Elasticsearch to start on boot
sudo update-rc.d elasticsearch defaults 95 10

# Restart Elasticsearch service
service elasticsearch restart

# Install ElasticHQ Plugin to view Elasticsearch Cluster Details http://elastichq.org
# To view these stats connect to http://logstashFQDNorIP:9200/_plugin/HQ/
/usr/share/elasticsearch/bin/plugin -install royrusso/elasticsearch-HQ

# Install elasticsearch Marvel Plugin Details http://www.elasticsearch.org/overview/marvel/
# To view these stats connect to http://logstashFQDNorIP:9200/_plugin/marvel
/usr/share/elasticsearch/bin/plugin -i elasticsearch/marvel/latest

# Install other elasticsearch plugins
# To view paramedic connect to http://logstashFQDNorIP:9200/_plugin/paramedic/index.html
/usr/share/elasticsearch/bin/plugin -install karmi/elasticsearch-paramedic
# To view elasticsearch head connect to http://logstashFQDNorIP:9200/_plugin/head/index.html
/usr/share/elasticsearch/bin/plugin -install mobz/elasticsearch-head

# Install elasticsearch curator http://www.elasticsearch.org/blog/curator-tending-your-time-series-indices/
apt-get -y install python-pip
pip install elasticsearch-curator

# Create /etc/cron.daily/elasticsearch_curator Cron Job and send output to logstash tagged as curator
tee -a /etc/cron.daily/elasticsearch_curator <<EOF
#!/bin/sh
curator delete --older-than 90 2>&1 | nc logstash 28778
curator close --older-than 30 2>&1 | nc logstash 28778
curator bloom --older-than 2 2>&1 | nc logstash 28778
curator optimize --older-than 2 2>&1 | nc logstash 28778

# Cleanup Marvel plugin indices
curator delete --older-than 60 -p .marvel- 2>&1 | nc logstash 28778
curator close --older-than 7 -p .marvel- 2>&1 | nc logstash 28778
curator bloom --older-than 2 -p .marvel- 2>&1 | nc logstash 28778
curator optimize --older-than 2 -p .marvel- 2>&1 | nc logstash 28778 

# Email report
#recipients="emailAdressToReceiveReport"
#subject="Daily Elasticsearch Curator Job Report"
#cat /var/log/elasticsearch_curator.log | mail -s $subject $recipients
EOF

# Make elasticsearch_curator executable
chmod +x /etc/cron.daily/elasticsearch_curator

# Logrotate job for elasticsearch_curator
tee -a /etc/logrotate.d/elasticsearch_curator <<EOF
/var/log/elasticsearch_curator.log {
        monthly
        rotate 12
        compress
        delaycompress
        missingok
        notifempty
        create 644 root root
}
EOF

# All Done
echo "Installation has completed!!"
echo "Now continue on and setup your ELK Frontend logstash processing nodes"
echo "${yellow}EveryThingShouldBeVirtual.com${NC}"
echo "${yellow}@mrlesmithjr${NC}"
echo "${yellow}Enjoy!!!${NC}"
