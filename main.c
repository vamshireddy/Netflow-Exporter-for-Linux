#include "common.h"
#ifndef PACKET
#define PACKET
#include "packet_handler.h"
#endif

#ifndef FLOW_CACHE
#define FLOW_CACHE
#include "flow_cache.h"
#endif

#ifndef MAIN
#define MAIN
#include "main.h"
#endif

// This thread will capture the packets from various interfaces and caches them into the flowcache

#define MAXBYTES2CAPTURE 2048

hash_table_t hashTable;
flow_cache_t flowCache;

void housekeeping()
{
	/* Set up flow cache */
	flowCache.first = NULL;
	flowCache.last = NULL;
	flowCache.flow_count = 0;

	/* Set up hash table */
	int i;
	for(i=0;i<HASH_BUCKETS;i++)
	{
		hashTable.list[i] = NULL;
	}
}

int main(int argc, char* argv[])
{
	pcap_t* pcap_fd = NULL;
	char errbuff[PCAP_ERRBUF_SIZE];
	char* device = "eth0";
	memset(errbuff,0, PCAP_ERRBUF_SIZE);

	/* Open the device */
	pcap_fd = pcap_open_live(device, MAXBYTES2CAPTURE, 0, 512, errbuff);
	if( pcap_fd == NULL )
	{
		printf("Cannot open the pcap\n");
		exit(0);
	}
	
	/* Apply filters to grab only tcp and udp IP packets */

	struct bpf_program* filter_s = (struct bpf_program*)malloc(sizeof(struct bpf_program));

	if( pcap_compile(pcap_fd, filter_s, "tcp or udp", 0, NULL ) == -1 )
	{
		perror("PCAP compile");
		return;
	}

	if( pcap_setfilter(pcap_fd, filter_s) == -1 )
	{
		perror("PCAP set filter\n");
		return;
	}
	
	/* Set up table and cache */
	housekeeping();

	/* Now capture the packets on this interface */	
	if( pcap_loop(pcap_fd, 0, handle_packet, NULL) == -1 )
	{
		printf("Error with the pcap loop\n");
		exit(0);
	}
}
