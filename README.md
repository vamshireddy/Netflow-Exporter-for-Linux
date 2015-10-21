# Netflow-Exporter-for-Linux
Cisco Netflow support for Linux. 

# Architecture
* This is an user level daemon that monitors the flows passing through the interfaces, maintaining a flow cache.
* Flow cache consists of details such as packet counts, packet fields like Src IP, dst IP, src Port, dst Port, Protocol, TCP headers, UDP headers, etc.
* Hash table is implemented for faster lookup of the flows. 
* Hash key is 5 tuple and MD5 hash is used to get a unique key out of these 5 tuples.
* It can also send these flow statistics to the configured netflow collector. 
* This can be used in moderate traffic Linux routers. Its compatible with Cisco Netflow version 9.
* Pcap library is used to capture the packets on the interfaces.
