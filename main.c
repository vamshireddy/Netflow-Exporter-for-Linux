#include "common.h"

// This thread will capture the packets from various interfaces and caches them into the flowcache

int main()
{
	int data_size;
	uint8_t buffer[MAX_SIZE];

	int sock_udp = socket(PF_INET , SOCK_RAW , IPPROTO_UDP);
	int sock_tcp = socket(PF_INET , SOCK_RAW , IPPROTO_TCP);
	int sock_icmp = socket(PF_INET , SOCK_RAW , IPPROTO_ICMP);
	
	if( sock_udp < 0 || sock_tcp < 0 || sock_icmp < 0 )
	{
		perror("Error in creating socket");
		exit(0);
	}

	while(1)
	{
		data_size = read(sock_icmp, buffer, MAX_SIZE);
		if( data_size < 0 )
		{
			perror("Error in recieving the data");
		}
		printf("got %d size packets\n", data_size);
	}
}
