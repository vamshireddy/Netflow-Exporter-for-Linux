#include "common.h"

#define HASH_BUCKETS 256
#define HASH_INPUT_LEN 13
#define DIGEST_LEN 16

/* Flow entry */
typedef struct flow_entry
{
	uint32_t time_captured;
	/* Key */
	uint32_t src_ipv4;
	uint32_t dst_ipv4;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	/* Key */
	uint8_t tos_ipv4;
	uint16_t id_ipv4;
	uint8_t ingress_int;
	uint8_t egress_int;
	uint64_t bytes;
	uint64_t packet_count;
	uint8_t flow_direction;
	uint8_t src_mac[6];
	uint8_t dst_mac[6];
	/* Additional fields */
	uint32_t next_hop_ipv4;
	uint64_t min_packet_len;
	uint64_t max_packet_len;
	uint8_t min_ttl_ipv4;
	uint8_t max_ttl_ipv4;
	// Timers : Active and passive
	uint64_t active_time;
	uint64_t passive_time;
	// LinkedList Pointers
	struct flow_entry* next;
	struct flow_entry* prev;
}flow_entry_t;

/* Cache */
typedef struct flow_cache
{
	flow_entry_t* first;
	flow_entry_t* last;
	uint64_t flow_count;
} flow_cache_t;

/* Flow hash table */
typedef struct table_entry
{
	flow_entry_t* flowentry;
	struct table_entry* next;
	struct table_entry* prev;
}table_entry_t;

typedef struct hash_table
{
	struct table_entry_t* list[HASH_BUCKETS];
}hash_table_t;

/* 
   This method will add a new flow to the cache if the flow is not present.
   If the flow is already present, then it updates the counters.
*/
int update_flow(char* src_int, uint8_t* ip_packet, struct pcap_pkthdr *packet_info);
/*
   This method will interate through the flows present and displays them.
*/
int show_flows();
/*
   This will delete the given entry from the flow cache
*/
int delete_flow(flow_entry_t* entry);

/* Creates a flow in the flow cache and also allocates a struct in hash table pointing to the flow cache entry created  */
flow_entry_t* create_flow(uint32_t src_ip, uint32_t dst_ip, uint16_t sport, uint16_t dport, uint8_t protocol);

/* This computes the bucket inside the hash table */
int compute_bucket(uint64_t hash);

/* Copy details */
int copy_details(flow_entry_t* entry, uint8_t* packet);

/* This will update the details of an exisiting flow */
void update_details(flow_entry_t* flow,uint8_t* packet, struct pcap_pkthdr* packet_info);

/* This will check if the flow exists in the flow cache. If flow exists, it returns the pointer to the flow entry, else NULL */
flow_entry_t* if_flow_exist(int bucket_no, uint32_t ip_src, uint32_t ip_dst, uint16_t src_port, uint16_t dst_port, uint8_t proto);

table_entry_t* create_bucket_node( flow_entry_t* entry, table_entry_t* prev, table_entry_t* next );

void add_to_bucket(int bucket_no, flow_entry_t* flow);

flow_entry_t* create_flow_node(flow_entry_t* prev, flow_entry_t* next);

/* HASH TABLE RELATED FUNCTIONS */
/* This will hash the flow 5 tuple to a bucket on the hash table */
int64_t hash_packet(uint32_t src_ip, uint32_t dst_ip, uint16_t sport, uint16_t dport, uint8_t protocol);
