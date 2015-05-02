#ifndef FLOW_CACHE
#define FLOW_CACHE
#include "flow_cache.h"
#endif
#ifndef PACKET
#define PACKET
#include "packet_handler.h"
#endif

#ifndef MAIN
#define MAIN
#include"main.h"
#endif

int update_flow(char* src_int, uint8_t* ip_packet, struct pcap_pkthdr *packet_info)
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
	printf("Header len: %d\n",size_ip);
	if( ip->ip_p == IP_PROTO_TCP )
	{
		printf("Its TCP packet\n");
		tcp = (tcp_hdr_t*)(ip_packet + size_ip);			
		hash = hash_packet(ip->ip_src, ip->ip_dst, tcp->tcp_sport, tcp->tcp_dport, ip->ip_p);
		src_port = tcp->tcp_sport;
		dst_port = tcp->tcp_dport;
	}
	else if( ip->ip_p == IP_PROTO_UDP )
	{
		printf("its UDP packet\n");
		udp = (udp_hdr_t*)(ip_packet + size_ip); 	
		hash = hash_packet(ip->ip_src, ip->ip_dst, udp->udp_sport, udp->udp_dport, ip->ip_p);
		src_port = udp->udp_sport;
		dst_port = udp->udp_dport;
	}
	else if( ip->ip_p == IP_PROTO_ICMP )
	{
		printf("ICMP packet\n");
		/* ICMP TODO */
	}
	
	printf("Hash is %lu\n",hash);

	/* Compute the bucket for this hash */
	int bucket_no = compute_bucket(hash);

	printf("Bucket no : %d\n",bucket_no);

	/* Check for the existence of the flow */
	flow_entry_t* flow = NULL;
	
	if( (flow = if_flow_exist(bucket_no, ip->ip_src, ip->ip_dst, src_port, dst_port, ip->ip_p)) != NULL )
	{
		printf("Flow exists\n");
		/* Flow exists in the Hash table. Now update the flow with the details */
		update_details(flow, ip_packet, packet_info);				
	}	
	else
	{
		printf("Flow not present\n");
		/* Flow not present in the hash table, creates a flow entry with the basic tuples ( 5 tuples ) */
		flow = create_flow(ip->ip_src, ip->ip_dst, src_port, dst_port, ip->ip_p);
		assert(flow!=NULL);
		/* Update the current packet to the flow */
		update_details(flow, ip_packet, packet_info);
		/* Init entries of flow */
		if( copy_details(flow, ip_packet) == -1 )
		{
			printf("Malformed packet while copying\n");
		}
	}
	show_flows();
}

flow_entry_t* if_flow_exist(int bucket_no, uint32_t ip_src, uint32_t ip_dst, uint16_t src_port, uint16_t dst_port, uint8_t proto)
{
	/* Check if the flow is present in the table */
	table_entry_t* entries = hashTable.list[bucket_no];	
	while( entries != NULL )
	{
		flow_entry_t* ent = entries->flowentry;
		if( ent->src_ipv4 == ip_src && ent->dst_ipv4 == ip_dst && ent->src_port == src_port && ent->dst_port == dst_port && ent->protocol == proto)
		{
			/* Matched */
			return ent;
		}
		entries = entries->next;
	}
	return NULL;
}

flow_entry_t* create_flow(uint32_t src_ip, uint32_t dst_ip, uint16_t sport, uint16_t dport, uint8_t protocol)
{
	/* Create flow in the flow cache and also in the hash table */
	flow_entry_t* node = NULL;
	if( ( flowCache.first == NULL && flowCache.last !=NULL ) || ( flowCache.first != NULL && flowCache.last ==NULL ) )
	{
		/* Error */
		return NULL;
	}
	else if( flowCache.first == NULL && flowCache.last == NULL )
	{
		node = create_flow_node(NULL, NULL);
		assert(node!=NULL);
		flowCache.first = node;
		flowCache.last = node;
	}
	else if( flowCache.first != NULL && flowCache.last != NULL )
	{	
		flow_entry_t* temp = flowCache.first;
		node = create_flow_node(NULL, temp);
		assert(node!=NULL);
		temp->prev = node;
		flowCache.first = node;
	}
	clear_flow(node);

	/* Now copy the fields */	
	node->src_ipv4 = src_ip;
	node->dst_ipv4 = dst_ip;
	node->src_port = sport;
	node->dst_port = dport;
	node->protocol = protocol;


	/* Add this node to the hash table */	
	uint64_t hash = hash_packet(src_ip, dst_ip, sport, dport, protocol);
	int bucket_no = compute_bucket(hash);
	
	add_to_bucket(bucket_no,node);
	/* Flow entry added to the bucket */
	return node;
}



/* Performs MD5 hash */
int64_t hash_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t sport, uint16_t dport, uint8_t protocol)
{
	uint8_t hash_str[HASH_INPUT_LEN];
	memcpy(hash_str, &src_ip, 4);
	memcpy(hash_str+4, &dst_ip, 4);
	memcpy(hash_str+8, &sport, 2);
	memcpy(hash_str+10, &dport, 2);
	memcpy(hash_str+12, &protocol, 1);

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
	/* Time */
	memcpy(&flow->time_captured,&packet_info->ts,sizeof(struct timeval));
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
	printf("Count: %d Bytes: %d\n",flow->packet_count, flow->bytes);
}


flow_entry_t* create_flow_node(flow_entry_t* prev, flow_entry_t* next)
{
	flow_entry_t* node = (flow_entry_t*)malloc(sizeof(flow_entry_t));
	assert(node!=NULL);
	node->prev = prev;
	node->next = next;
	return node;
}


int clear_flow(flow_entry_t* flow)
{
	bzero((void*)&flow->time_captured, sizeof(struct timeval));
	flow->src_ipv4 = 0;
	flow->dst_ipv4 = 0;
	flow->src_port = 0;
	flow->dst_port = 0;
	flow->protocol = 0;
	flow->tos_ipv4 = 0;
	flow->id_ipv4 = 0;
	flow->ingress_int = NULL;
	flow->egress_int = NULL;
	flow->bytes = 0;
	flow->packet_count = 0;
	flow->flow_direction = 0;
	bzero(flow->src_mac, 8);
	bzero(flow->dst_mac, 8);
	flow->next_hop_ipv4 = 0;
	flow->min_packet_len = ULONG_MAX;
	flow->max_packet_len = 0;
	flow->min_ttl_ipv4 = UCHAR_MAX;
	flow->max_ttl_ipv4 = 0;
}


int show_flows()
{
	printf("\n\n\n");
	flow_entry_t* temp = flowCache.first;
	while( temp!=NULL )
	{
		printf("There is a flow\n");	
		temp = temp->next;
	}
	printf("\n\n\n");
}


int copy_details(flow_entry_t* flow, uint8_t* ip_packet) 
{
	/* TODO */
	return 1;
}


void add_to_bucket(int bucket_no, flow_entry_t* flow)
{
	table_entry_t* old_node = hashTable.list[bucket_no];
	table_entry_t* new_node = NULL;
	if( old_node == NULL )
	{
		new_node = create_bucket_node(flow, NULL, NULL);
		assert(new_node!=NULL);
	}
	else
	{
		new_node = create_bucket_node(flow, NULL, old_node);
		assert(new_node!=NULL);
		old_node->prev = new_node;
	}
	hashTable.list[bucket_no] = new_node;
}

table_entry_t* create_bucket_node( flow_entry_t* entry, table_entry_t* prev, table_entry_t* next )
{
	table_entry_t* temp = (table_entry_t*)malloc(sizeof(table_entry_t));				
	temp->flowentry = entry;
	temp->prev = prev;
	temp->next = next;
	return temp;
}
