#include "packet_handler.h"
#ifndef FLOW_CACHE
#define FLOW_CACHE
#include "flow_cache.h"
#endif

hash_table_t hash_table;
flow_cache_t flow_cache;

void handle_packet(uint8_t *args, const struct pcap_pkthdr *header, uint8_t *packet)
{
	return;
	// TODO add interface 
	char* interface = "eth0";
	/* Check the packet header */
	printf("Packet captured: Length: %d, %d\n",header->caplen, header->len);
	/* Check the packer type */
	ether_hdr_t* ethernet = (ether_hdr_t*)packet;
	if( ntohs(ethernet->ether_type) != 0x0800 )
	{
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
		update_flow(&flow_cache, interface, packet, &hash_table, header);
	}
	free(ethernet);
	free(ip);
	free(header);
	free(packet);
}

int sanity_checks(uint8_t* packet)
{
	printf("Sanity\n");
	return 1;	
}
