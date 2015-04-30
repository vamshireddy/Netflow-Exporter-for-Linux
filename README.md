# Netflow-Exporter-for-Linux
Netflow support for Linux. This is an user level daemon, which monitors the packets entering and leaving on all the interfaces. It also sends these flow statistics to the configured netflow collector. This can be used in moderate traffic Linux routers. Its compatible with Cisco Netflow version 9.

* Pcap is used to capture the packets on all the interfaces.
* Netflow Templates can be dynamically added or deleted.
