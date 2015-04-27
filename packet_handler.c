#include "packet_handler.h"


void handle_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet)
{
	/* Check the header */
	printf("Packet captured: Length: %d, %d\n",header->caplen, header->len);

	/* Create a flow if its not there */
	ether_hdr_t* ethernet = (ether_hdr_t*)malloc(sizeof(ether_hdr_t));
	ethernet = (ether_hdr_t*)packet;
	if( ntohs(ethernet->ether_type) != 0x0800 )
	{
		/* not an IP packet */
		return;
	}
	/* IP Packet */
	ip_hdr_t* ip = (ip_hdr_t*)malloc(sizeof(ip_hdr_t));
	ip = (ip_hdr_t*)(packet + ETHER_HDR_LEN);
	int size_ip = IP_HL(ip)*4;
	if( size_ip < 20 )
	{
		printf("Bad IP Packet\n");
		return;
	}
	struct in_addr* src_addr_s = (struct in_addr*)malloc(sizeof(struct in_addr));;
	memcpy(&(src_addr_s->s_addr), &(ip->ip_src), 4);
	struct in_addr* dst_addr_s = (struct in_addr*)malloc(sizeof(struct in_addr));;
	memcpy(&(dst_addr_s->s_addr), &(ip->ip_dst), 4);

	char src_ip_str[INET_ADDRSTRLEN];
	char dst_ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, src_addr_s, src_ip_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, dst_addr_s, dst_ip_str, INET_ADDRSTRLEN);
	printf("Src IP: %s and Dst IP: %s\n",src_ip_str, dst_ip_str);
}

