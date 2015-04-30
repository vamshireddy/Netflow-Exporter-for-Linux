#include "common.h"
#ifndef PACKET
#define PACKET
#include "packet_handler.h"
#endif
// This thread will capture the packets from various interfaces and caches them into the flowcache

#define MAXBYTES2CAPTURE 2048

int main()
{
	pcap_t* pcap_fd = NULL;
	char errbuff[PCAP_ERRBUF_SIZE];
	char* device = "eth0";
	memset(errbuff,0, PCAP_ERRBUF_SIZE);

	/* Open the device */
	pcap_fd = pcap_open_live(device, MAXBYTES2CAPTURE, 0, 512, errbuff);
	if( pcap_fd == -1 )
	{
		printf("Cannot open the pcap\n");
		exit(0);
	}
	/* Now capture the packets on this interface */	
	if( pcap_loop(pcap_fd, 0, handle_packet, NULL) == -1 )
	{
		printf("Error with the pcap loop\n");
		exit(0);
	}
}
