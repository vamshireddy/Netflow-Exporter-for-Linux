#include "flow_cache.h"


void update_flow(flow_cache* cache, uint8_t src_int, uint8_t* ip_packet, hash_table_t* table)
{
	/* Get the flow tuples */
	uint16_t src_port = 0;
	uint16_t dst_port = 0;
	tcp_hdr_t* tcp = NULL;
	udp_hdr_t* udp = NULL;
	
	/* Calculate the Hash for the five tuple */
	
	uint64_t hash;

	ip_hdr_t* ip = (ip_hdr_t*)ip_packet;
	
	if( ip->p == IP_PROTO_TCP )
	{
		tcp = (tcp_hdr_t*)(ip_packet+ip_header);			
		hash = hash_packet(ip->ip_src, ip->ip_dst, tcp->tcp_sport, tcp->tcp_dport, ip->p);
		src_port = tcp->tcp_sport;
		dst_port = tcp->tcp_dport;
	}
	else if( ip->p == IP_PROTO_UDP )
	{
		udp = (udp_hdr_t*)(ip_packet+ip_header); 	
		hash = hash_packet(ip->ip_src, ip->ip_dst, udp->udp_sport, udp->udp_dport, ip->p);
		src_port = udp->udp_sport;
		dst_port = udp->udp_dport;
	}
	
	/* Compute the bucket for this hash */
	int bucket = compute_bucket(hash);

	/* Check for the existence of the flow */
	flow_entry_t* flow = NULL;
	if( flow = if_flow_exist(table, bucket, ip->ip_src, ip->ip_dst, src_port, dst_port, ip->p)  )
	{
		/* Flow exists in the Hash table. Now update the flow with the details */
		update_details(flow, packet, packet_size);				
	}	
	else
	{
		/* Flow not present in the hash table, creates a flow entry with the basic tuples ( 5 tuples ) */
		flow = create_flow(cache, table, ip_packet, packet_size);
		if( copy_details(flow, ip_packet) == -1 )
		{
			printf("Malformed packet while copying\n");
		}
	}
}
