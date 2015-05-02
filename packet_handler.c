#include "packet_handler.h"
#ifndef FLOW_CACHE
#define FLOW_CACHE
#include "flow_cache.h"
#endif

void handle_packet(uint8_t *args, const struct pcap_pkthdr *header, uint8_t *packet)
{
	char* interface = "eth0";
	
	/* Check the packet header */
	printf("Packet captured: Length: %d, %d\n",header->caplen, header->len);
	
	/* Check the packer type */
	ether_hdr_t* ethernet = (ether_hdr_t*)packet;
	if( ntohs(ethernet->ether_type) != 0x0800 )
	{
		printf("ERROR: Not an IP Packet\n");
		/* not an IP packet */
		return;
	}

	/* IP Packet */
	ip_hdr_t* ip = (ip_hdr_t*)(packet + ETHER_HDR_LEN);
	int size_ip = IP_HL(ip)*4;
	if( size_ip < 20 )
	{
		printf("Bad IP Packet\n");
		return;
	}
	/* Sanity checks include ip_checksum, udp or tcp checksum, header_len checks */
	if( sanity_checks(packet) == 1 )
	{
		printf("Updating flow\n");
		update_flow(interface, packet+ETHER_HDR_LEN, header);
	}
}

int sanity_checks(uint8_t* packet)
{
	printf("Sanity\n");
	return 1;	
}
