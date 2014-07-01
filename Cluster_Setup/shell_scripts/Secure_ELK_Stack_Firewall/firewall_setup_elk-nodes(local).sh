#!/bin/bash

# Setup Pause function
function pause(){
read -p "$*"
}

# Create/Modify firewall rules on elk nodes
# These rules will force users to go directly through the HAProxy LB VIP and not allow users to connect directly to any of the ELK nodes for ES or Kibana
# In order to use this script you must allow ssh key based login to your ELK nodes as root
# You can add additional TCP/UDP ports required for your setup in the respective txt files
# You will also need to modify the txt files which include your actual ELK nodes in the respective txt file
# Add any additional node that you want to grant access to your ELK nodes into the admin_stations.txt file
# Keep HAProxy nodes separate as they need to be availabe from any node on your network but you may also want to tighten these down if requirements dictate that
# Default Non-ELK related rules are any ports you would like to allow by default...Generally this will only be SSH TCP/22. So these rules will not be related to the ELK stack.
# ELK related rules are the ports required for any of the ELK components to communicate all of the way up to the HAProxy LB's.
# ELK related rules would be assigned as unrestricted - Allowed from any node on your network and restricted - Only allowed from the nodes within your ELK stack
#

	# Flush existing rules and chains
	echo "Flushing existing Firewall rules"
	sudo iptables -P INPUT ACCEPT
	sudo iptables -P FORWARD ACCEPT
	sudo iptables -F
	sudo iptables -X

	# Create new chains and setup logging
	echo "Setting up firewall chains and logging"
	sudo iptables -N DEFAULT-Allowed
	sudo iptables -N ELK-RELATED-Allowed
	sudo iptables -N LOGGING-Allowed
	sudo iptables -A LOGGING-Allowed -m limit --limit 2/min -j LOG --log-prefix "IPTables-Allowed: " --log-level 4
	sudo iptables -A LOGGING-Allowed -j ACCEPT
	sudo iptables -N LOGGING-Dropped
	sudo iptables -A LOGGING-Dropped -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
	sudo iptables -A LOGGING-Dropped -j REJECT --reject-with icmp-proto-unreachable

	# Allow all established and related connections
	echo "Allowing all Established,Related connections"
	sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j LOGGING-Allowed

	# Allow all connections from localhost to localhost
	echo "Allowing all connections from localhost"
	sudo iptables -A INPUT -i lo -j LOGGING-Allowed

	# Drop INVALID headers and checksums, invalid TCP flags, invalid ICMP messages and out of sequence packets
	echo "Dropping INVALID headers and checksums, invalid TCP flags, invalid ICMP messages and out of sequence packets"
	sudo iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

	# Allow ICMP for everything
	echo "Allowing ICMP Firewall rules"
	sudo iptables -A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j LOGGING-Allowed

	# Setup default rules not related to ELK
	echo "Applying all default non-ELK related ports"
	for defaultportallow in $(cat firewall_default_tcp_ports_allowed.txt); do
			echo "Allowing TCP port: " $defaultportallow
			sudo iptables -A INPUT -p tcp --dport $defaultportallow -j DEFAULT-Allowed
			sudo iptables -A DEFAULT-Allowed -p tcp --dport $defaultportallow -m conntrack --ctstate NEW -j LOGGING-Allowed
	done
	for defaultportallow in $(cat firewall_default_udp_ports_allowed.txt); do
			echo "Allowing UDP port: " $defaultportallow
			sudo iptables -A INPUT -p udp --dport $defaultportallow -j DEFAULT-Allowed
			sudo iptables -A DEFAULT-Allowed -p udp --dport $defaultportallow -m conntrack --ctstate NEW -j LOGGING-Allowed
	done

# Apply non resricted ELK Ports
	echo "Applying all ELK unrestricted firewall rules"
	for portallow in $(cat firewall_unrestricted_tcp_ports_allowed.txt); do
			echo "Allowing TCP port: " $portallow
			# Setup first needed rule to send rule to chain for each protocol
			sudo iptables -A INPUT -p tcp --dport $portallow -j ELK-RELATED-Allowed
			sudo iptables -A ELK-RELATED-Allowed -p tcp --dport $portallow -m conntrack --ctstate NEW -j LOGGING-Allowed
	done
	for portallow in $(cat firewall_unrestricted_udp_ports_allowed.txt); do
			echo "Allowing UDP port: " $portallow
			# Setup first needed rule to send rule to chain for each protocol
			sudo iptables -A INPUT -p udp --dport $portallow -j ELK-RELATED-Allowed
			sudo iptables -A ELK-RELATED-Allowed -p udp --dport $portallow -m conntrack --ctstate NEW -j LOGGING-Allowed
	done

# Apply allow ELK related firewall rules
	# Apply TCP Ports
	echo "Applying all ELK related firewall rules"
	for portallow in $(cat firewall_restricted_tcp_ports_allowed.txt); do
			# allowing other ELK nodes access
			sudo iptables -A INPUT -p tcp --dport $portallow -j ELK-RELATED-Allowed
			for node in $(cat elk-nodes.txt); do
					echo "Allowing TCP port: " $portallow "From ELK node: " $node
					# Setup first needed rule to send rule to chain for each protocol
					sudo iptables -A ELK-RELATED-Allowed -p tcp --dport $portallow -s $node -m conntrack --ctstate NEW -j LOGGING-Allowed
			done
			# allowing haproxy nodes access
			for node in $(cat elk-haproxy-nodes.txt); do
					echo "Allowing TCP port: " $portallow "From haproxy node: " $node
					sudo iptables -A ELK-RELATED-Allowed -p tcp --dport $portallow -s $node -m conntrack --ctstate NEW -j LOGGING-Allowed
			done
			# allowing admin user stations access
			for station in $(cat admin_stations.txt); do
					echo "Allowing TCP port: " $portallow "From admin station: " $station
					sudo iptables -A ELK-RELATED-Allowed -p tcp --dport $portallow -s $station -m conntrack --ctstate NEW -j LOGGING-Allowed
			done
	done
	# Apply UDP Ports
	for portallow in $(cat firewall_restricted_udp_ports_allowed.txt); do
			# allowing other ELK nodes access
			sudo iptables -A INPUT -p udp --dport $portallow -j ELK-RELATED-Allowed
			for node in $(cat elk-nodes.txt); do
					echo "Allowing UDP port: " $portallow "From ELK node: " $node
					# Setup first needed rule to send rule to chain for each protocol
					sudo iptables -A ELK-RELATED-Allowed -p udp --dport $portallow -s $node -m conntrack --ctstate NEW -j LOGGING-Allowed
			done
			# allowing haproxy nodes access
			for node in $(cat elk-haproxy-nodes.txt); do
					echo "Allowing UDP port: " $portallow "From haproxy node: " $node
					sudo iptables -A ELK-RELATED-Allowed -p udp --dport $portallow -s $node -m conntrack --ctstate NEW -j LOGGING-Allowed
			done
			# allowing admin user stations access
			for station in $(cat admin_stations.txt); do
					echo "Allowing UDP port: " $portallow "From admin station: " $station
					sudo iptables -A ELK-RELATED-Allowed -p udp --dport $portallow -s $station -m conntrack --ctstate NEW -j LOGGING-Allowed
			done
	done

# Apply deny firewall rules for everything else other than allowed above
	echo "Applying Firewall drop rules"
	sudo iptables -A INPUT -j LOGGING-Dropped
	sudo iptables -A FORWARD -j LOGGING-Dropped

# Apply Default Filtering Policy
	echo "Setting Default Firewall policy to drop"
	sudo iptables -P INPUT DROP
	sudo iptables -P FORWARD DROP
	sudo iptables -P OUTPUT ACCEPT

# Save Firewall rules
 echo "Saving Firewall rules"
        sudo sh -c "iptables-save > /etc/iptables.rules"
        echo "Setting IPTables save|restore in /etc/network/interfaces to start on boot"
        sudo cp /etc/network/interfaces /etc/network/interfaces.$datestamp
        sudo sed -i -e 's|pre-up iptables-restore < /etc/iptables.rules||' /etc/network/interfaces
        sudo sed -i -e 's|post-down||' /etc/network/interfaces
        sudo sed -i -e 's|post-down iptables-restore < /etc/iptables.downrules||' /etc/network/interfaces
        sudo sed -i -e 's|iptables-save -c > /etc/iptables.rules||' /etc/network/interfaces
        sudo echo 'pre-up iptables-restore < /etc/iptables.rules' >> /etc/network/interfaces
        sudo echo 'post-down iptables-save -c > /etc/iptables.rules' >> /etc/network/interfaces
