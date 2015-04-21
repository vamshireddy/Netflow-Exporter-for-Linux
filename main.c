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
	int max = (sock_udp > sock_tcp) ? ( (sock_udp > sock_icmp)? sock_udp:sock_icmp) : ((sock_tcp > sock_icmp)? sock_tcp : sock_icmp );
	fd_set fds;
	
	while(1)
	{
		FD_ZERO(&fds);
		FD_SET(sock_udp,&fds);
		FD_SET(sock_icmp,&fds);
		FD_SET(sock_tcp,&fds);
		int ret = select(max+1, &fds, NULL, NULL, NULL);
		if( ret < 0 )
		{
			perror("Error in select");
			continue;
		}
		else if( ret == 0 )
		{
			printf("None ready\n");
			continue;
		}

		if( FD_ISSET(sock_udp, &fds) )
		{
			// Its a UDP packet
			data_size = read(sock_icmp, buffer, MAX_SIZE);
			if( data_size < 0 )
			{
				perror("Error in recieving the data");
			}
			printf("got %d size packets\n", data_size);
		}
		if( FD_ISSET(sock_tcp, &fds))
		{
			// Its a TCP packet
			printf("Its a TCP packet\n");

		}
		if( FD_ISSET(sock_icmp, &fds))
		{
			// Its an ICMP packet
			printf("its an ICMP packet\n");
		}
	}
	/*int fd = socket(PF_PACKET, SOCK_RAW, IPPROTO_RAW);
	while(1)
	{
		int r = read(fd, buffer, MAX_SIZE);
		printf("Read %d bytes\n",r);
	}*/
}
