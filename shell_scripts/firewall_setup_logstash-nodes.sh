#!/bin/bash

# Setup Pause function
function pause(){
   read -p "$*"
}

# Create/Modify firewall rules on logstash nodes

for server in $(cat logstash_nodes.txt); do
        # Flush existing rules and chains
        echo "Flushing existing Firewall rules on: " $server
        ssh root@$server "iptables -P INPUT ACCEPT"
        ssh root@$server "iptables -P FORWARD ACCEPT"
        ssh root@$server "iptables -F"
        ssh root@$server "iptables -X"

        # Create new chains and setup logging
        echo "Setting up firewall chains and logging on" $server
        ssh root@$server "iptables -N DEFAULT-Allowed"
        ssh root@$server "iptables -N ELK-RELATED-Allowed"
        ssh root@$server "iptables -N LOGGING-Allowed"
        ssh root@$server "iptables -A LOGGING-Allowed -m limit --limit 2/min -j LOG --log-prefix "IPTables-Allowed: " --log-level 4"
        ssh root@$server "iptables -A LOGGING-Allowed -j ACCEPT"
        ssh root@$server "iptables -N LOGGING-Dropped"
        ssh root@$server "iptables -A LOGGING-Dropped -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4"
        ssh root@$server "iptables -A LOGGING-Dropped -j REJECT --reject-with icmp-proto-unreachable"

        # Allow all established and related connections
        echo "Allowing all Established,Related connections on server: " $server
        ssh root@$server "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j LOGGING-Allowed"

        # Allow all connections from localhost to localhost
        echo "Allowing all connections from localhost on server:" $server
        ssh root@$server "iptables -A INPUT -i lo -j LOGGING-Allowed"

        # Drop INVALID headers and checksums, invalid TCP flags, invalid ICMP messages and out of sequence packets
        echo "Dropping INVALID headers and checksums, invalid TCP flags, invalid ICMP messages and out of sequence packets"
        ssh root@$server "iptables -A INPUT -m conntrack --ctstate INVALID -j DROP"

        # Allow ICMP for everything
        echo "Allowing ICMP Firewall rules on: " $server
        ssh root@$server "iptables -A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j LOGGING-Allowed"

        # Setup default rules not related to ELK
        echo "Applying all default non-ELK related ports"
        for defaultportallow in $(cat firewall_default_tcp_ports_allowed_logstash-nodes.txt); do
                echo "Allowing TCP port: " $defaultportallow "On Server: " $server
                ssh root@$server "iptables -A INPUT -p tcp --dport $defaultportallow -j DEFAULT-Allowed"
                ssh root@$server "iptables -A DEFAULT-Allowed -p tcp --dport $defaultportallow -m conntrack --ctstate NEW -j LOGGING-Allowed"
        done
        for defaultportallow in $(cat firewall_default_udp_ports_allowed_logstash-nodes.txt); do
                echo "Allowing UDP port: " $defaultportallow "On Server: " $server
                ssh root@$server "iptables -A INPUT -p udp --dport $defaultportallow -j DEFAULT-Allowed"
                ssh root@$server "iptables -A DEFAULT-Allowed -p udp --dport $defaultportallow -m conntrack --ctstate NEW -j LOGGING-Allowed"
        done
done

# Apply non resricted ELK Ports
for server in $(cat logstash_nodes.txt); do
	echo "Applying all ELK unrestricted firewall rules on: " $server
	for portallow in $(cat firewall_unrestricted_tcp_ports_allowed_logstash-nodes.txt); do
		echo "Allowing TCP port: " $portallow "On server: " $server
		# Setup first needed rule to send rule to chain for each protocol
		ssh root@$server "iptables -A INPUT -p tcp --dport $portallow -j ELK-RELATED-Allowed"
		ssh root@$server "iptables -A ELK-RELATED-Allowed -p tcp --dport $portallow -m conntrack --ctstate NEW -j LOGGING-Allowed"
	done
	for portallow in $(cat firewall_unrestricted_udp_ports_allowed_logstash-nodes.txt); do
		echo "Allowing UDP port: " $portallow "On server: " $server
		# Setup first needed rule to send rule to chain for each protocol
		ssh root@$server "iptables -A INPUT -p udp --dport $portallow -j ELK-RELATED-Allowed"
		ssh root@$server "iptables -A ELK-RELATED-Allowed -p udp --dport $portallow -m conntrack --ctstate NEW -j LOGGING-Allowed"
	done
done

# Apply allow ELK related firewall rules
for server in $(cat logstash_nodes.txt); do
	# Apply TCP Ports
	echo "Applying all ELK related firewall rules on: " $server
	for portallow in $(cat firewall_restricted_tcp_ports_allowed_logstash-nodes.txt); do
		# allowing other logstash nodes access
		ssh root@$server "iptables -A INPUT -p tcp --dport $portallow -j ELK-RELATED-Allowed"
		for node in $(cat logstash_nodes.txt); do
			echo "Allowing TCP port: " $portallow "From logstash node: " $node "On server: " $server
			# Setup first needed rule to send rule to chain for each protocol
			ssh root@$server "iptables -A ELK-RELATED-Allowed -p tcp --dport $portallow -s $node -m conntrack --ctstate NEW -j LOGGING-Allowed"
		done
		# allowing haproxy nodes access
		for node in $(cat haproxy_nodes.txt); do
			echo "Allowing TCP port: " $portallow "From haproxy node: " $node "On server: " $server
			ssh root@$server "iptables -A ELK-RELATED-Allowed -p tcp --dport $portallow -s $node -m conntrack --ctstate NEW -j LOGGING-Allowed"
		done
		# allowing admin user stations access
		for station in $(cat admin_stations.txt); do
			echo "Allowing TCP port: " $portallow "From admin station: " $station "On server: " $server
			ssh root@$server "iptables -A ELK-RELATED-Allowed -p tcp --dport $portallow -s $station -m conntrack --ctstate NEW -j LOGGING-Allowed"
		done
	done
	# Apply UDP Ports
	for portallow in $(cat firewall_restricted_udp_ports_allowed_logstash-nodes.txt); do
		# allowing other logstash nodes access
		ssh root@$server "iptables -A INPUT -p udp --dport $portallow -j ELK-RELATED-Allowed"
		for node in $(cat logstash_nodes.txt); do
			echo "Allowing UDP port: " $portallow "From logstash node: " $node "On server: " $server
			# Setup first needed rule to send rule to chain for each protocol
			ssh root@$server "iptables -A ELK-RELATED-Allowed -p udp --dport $portallow -s $node -m conntrack --ctstate NEW -j LOGGING-Allowed"
		done
		# allowing haproxy nodes access
		for node in $(cat haproxy_nodes.txt); do
			echo "Allowing UDP port: " $portallow "From haproxy node: " $node "On server: " $server
			ssh root@$server "iptables -A ELK-RELATED-Allowed -p udp --dport $portallow -s $node -m conntrack --ctstate NEW -j LOGGING-Allowed"
		done
		# allowing admin user stations access
		for station in $(cat admin_stations.txt); do
			echo "Allowing UDP port: " $portallow "From admin station: " $station "On server: " $server
			ssh root@$server "iptables -A ELK-RELATED-Allowed -p udp --dport $portallow -s $station -m conntrack --ctstate NEW -j LOGGING-Allowed"
		done
	done
done

# Apply deny firewall rules for everything else other than allowed above
for server in $(cat logstash_nodes.txt); do
	echo "Applying Firewall drop rules on: " $server
	ssh root@$server "iptables -A INPUT -j LOGGING-Dropped"
	ssh root@$server "iptables -A FORWARD -j LOGGING-Dropped"
done

# Apply Default Filtering Policy
for server in $(cat logstash_nodes.txt); do
	echo "Setting Default Firewall policy to drop on: " $server
	ssh root@$server "iptables -P INPUT DROP"
	ssh root@$server "iptables -P FORWARD DROP"
	ssh root@$server "iptables -P OUTPUT ACCEPT"
done

# Save Firewall rules
for server in $(cat logstash_nodes.txt); do
	echo "Saving Firewall rules on: " $server
done
