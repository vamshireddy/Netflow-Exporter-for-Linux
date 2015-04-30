#include "flow_cache.h"

void update_flow(flow_cache_t* cache, uint8_t src_int, uint8_t* ip_packet, hash_table_t* table, struct pcap_pkthdr *packet_info)
{
	/* Get the flow tuples */
	uint16_t src_port = 0;
	uint16_t dst_port = 0;
	tcp_hdr_t* tcp = NULL;
	udp_hdr_t* udp = NULL;	
	/* Calculate the Hash for the five tuple */
	
	uint64_t hash;

	ip_hdr_t* ip = (ip_hdr_t*)ip_packet;
	int size_ip = IP_HL(ip)*4;
	if( ip->ip_p == IP_PROTO_TCP )
	{
		tcp = (tcp_hdr_t*)(ip_packet + size_ip);			
		hash = hash_packet(ip->ip_src, ip->ip_dst, tcp->tcp_sport, tcp->tcp_dport, ip->ip_p);
		src_port = tcp->tcp_sport;
		dst_port = tcp->tcp_dport;
	}
	else if( ip->ip_p == IP_PROTO_UDP )
	{
		udp = (udp_hdr_t*)(ip_packet + size_ip); 	
		hash = hash_packet(ip->ip_src, ip->ip_dst, udp->udp_sport, udp->udp_dport, ip->ip_p);
		src_port = udp->udp_sport;
		dst_port = udp->udp_dport;
	}
	else
	{
		/* ICMP TODO */
	}

	/* Compute the bucket for this hash */
	int bucket_no = compute_bucket(hash);

	/* Check for the existence of the flow */
	flow_entry_t* flow = NULL;
	if( (flow = if_flow_exist(table, bucket_no, ip->ip_src, ip->ip_dst, src_port, dst_port, ip->ip_p)) != NULL )
	{
		/* Flow exists in the Hash table. Now update the flow with the details */
		update_details(flow, ip_packet, packet_info);				
	}	
	else
	{
		/* Flow not present in the hash table, creates a flow entry with the basic tuples ( 5 tuples ) */
		flow = create_flow(cache, table, ip->ip_src, ip->ip_dst, src_port, dst_port, ip->ip_p);
		if( copy_details(flow, ip_packet) == -1 )
		{
			printf("Malformed packet while copying\n");
		}
	}
}

flow_entry_t* if_flow_exist(hash_table_t* table, int bucket_no, uint32_t ip_src, uint32_t ip_dst, uint16_t src_port, uint16_t dst_port, uint8_t proto)
{
	/* Check if the flow is present in the table */
	table_entry_t* entries = table->list[bucket_no];	
	while( entries->next != NULL )
	{
		flow_entry_t* ent = entries->flowentry;
		if( ent->src_ipv4 == ip_src && ent->dst_ipv4 == ip_dst && ent->src_port == src_port && ent->dst_port == dst_port && ent->protocol == proto)
		{
			/* Matched */
			return ent;
		}
	}
	return NULL;
}

flow_entry_t* create_flow(flow_cache_t* cache, hash_table_t* table,uint32_t src_ip, uint32_t dst_ip, uint16_t sport, uint16_t dport, uint8_t protocol)
{
	
}



/* Performs MD5 hash */
int64_t hash_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t sport, uint16_t dport, uint8_t protocol)
{
	uint8_t hash_str[HASH_INPUT_LEN];
	memcpy(hash_str, src_ip, 4);
	memcpy(hash_str+4, dst_ip, 4);
	memcpy(hash_str+8, sport, 2);
	memcpy(hash_str+10, dport, 2);
	memcpy(hash_str+12, protocol, 1);

	/* Hash the string */
	uint8_t digest[DIGEST_LEN];
	MD5_CTX context;
	MD5_Init(&context);
	MD5_Update(&context, hash_str, HASH_INPUT_LEN);
	MD5_Final(digest, &context);
	
	uint64_t result;
	uint8_t* ptr = (uint8_t*)&result;
	/* Convert the 128 bit digest to 64 bit long int (least significant 8 bytes)*/
	int i;
	for(i=0;i<8;i++)
	{
		memcpy(ptr, digest+15-i, 1);
		ptr++;
	}
	return result;
}


int compute_bucket(uint64_t hash)
{
	return hash % HASH_BUCKETS;	
}

void update_details(flow_entry_t* flow, uint8_t* packet, struct pcap_pkthdr* packet_info)
{
	/* Update the packet size and count to the flow */
	flow->packet_count++;
	flow->bytes += packet_info->len;
	/* Update min and max len */
	if( packet_info->len < flow->min_packet_len )
	{
		flow->min_packet_len = packet_info->len;
	}
	if( packet_info->len < flow->max_packet_len )
	{
		flow->max_packet_len = packet_info->len;
	}

	/* Update the min and max ttl */
	ip_hdr_t* ip = (ip_hdr_t*)packet;
	if( ip->ip_ttl < flow->min_ttl_ipv4 )
	{
		flow->min_ttl_ipv4 = ip->ip_ttl;		
	}
	if( ip->ip_ttl > flow->max_ttl_ipv4 )
	{
		flow->max_ttl_ipv4 = ip->ip_ttl;
	}
}
