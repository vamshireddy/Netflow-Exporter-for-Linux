#include "common.h"
#include "packet_handler.h"

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

	if (pcap_datalink(pcap_fd) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", device);
   		return;
   	}	
	/* Now capture the packets on this interface */	
	pcap_loop(pcap_fd, -1, handle_packet, NULL);
}
