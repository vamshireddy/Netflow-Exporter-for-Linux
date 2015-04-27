#include "common.h"

#define HASH_BUCKETS 256

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
} flow_entry_t;

/* Cache */
typedef struct flow_cache
{
	flow_entry* first;
	flow_entry* last;
	uint64_t flow_count;
} flow_cache_t;

/* Flow hash table */
typedef struct table_entry
{
	flow_entry_t* entry;
	struct table_entry* next;
}table_entry_t;

typedef struct hash_table
{
	struct table_entry* list[HASH_BUCKETS];

}hash_table_t;

/* 
   This method will add a new flow to the cache if the flow is not present.
   If the flow is already present, then it updates the counters.
*/
int update_flow(flow_cache* cache, uint8_t src_int, uint8_t* ip_packet, hash_table_t* table);
/*
   This method will interate through the flows present and displays them.
*/
int show_flows(flow_cache* cache);
/*
   This will delete the given entry from the flow cache
*/
int delete_flow(flow_cache* cache, flow_entry* entry, hash_table_t* table);

/* Creates a flow in the flow cache and also allocates a struct in hash table pointing to the flow cache entry created  */
flow_entry_t* create_flow(flow_cache* cache, hash_table_t* table, uint8_t* packet);

/* This computes the bucket inside the hash table */
int compute_bucket(uint64_t hash);

/* Copy details */
void copy_details(flow_entry_t* entry, uint8_t* packet);

/* This will update the details of an exisiting flow */
void update_details(flow_entry_t* flow,uint8_t* packet,uint64_t packet_size);

/* This will check if the flow exists in the flow cache. If flow exists, it returns the pointer to the flow entry, else NULL */
flow_entry_t* if_flow_exist(hash_table_t* table, table_entry_t* bucket, uint32_t ip_src, uint32_t ip_dst, uint16_t src_port, uint16_t dst_port, \
			uint8_t proto);


/* HASH TABLE RELATED FUNCTIONS */
/* This will hash the flow 5 tuple to a bucket on the hash table */
int64_t hash_packet(uint16_t src_ip, uint32_t dst_ip, uint16_t sport, uint16_t dport, uint16_t protocol);
