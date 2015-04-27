#include "common.h"

typedef struct flow_entry
{
	uint32_t time_captured;
	uint32_t src_IP;
	uint32_t dst_IP;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	uint8_t tos;
	uint8_t ingress_int;
	uint8_t egress_int;
	uint64_t bytes;
	uint64_t packet_count;
	// Timers : Active and passive
	uint64_t active_time;
	uint64_t passive_time;
	// LinkedList Pointers
	struct flow_entry* next;
	struct flow_entry* prev;
} flow_entry;

typedef struct flow_cache
{
	flow_entry* entries;
	flow_entry* first;
	flow_entry* last;
	uint64_t flow_count;
} flow_cache;

/* 
   This method will add a new flow to the cache if the flow is not present.
   If the flow is already present, then it updates the counters.
*/
int add_flow(flow_cache* cache, uint8_t src_int, uint8_t* ip_packet);
/*
   This method will interate through the flows present and displays them.
*/
int show_flows(flow_cache* cache);

/*
   This will delete the given entry from the flow cache
*/
int delete_flow(flow_cache* cache, flow_entry* entry);
