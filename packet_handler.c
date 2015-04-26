#include "packet_handler.h"


int find_trans_protocol(uint8_t* packet)
{
	uint8_t code = packet[9];
	if( code == 6 )
	{
		// TCP
		return 1;
	}
	else if( code == 17 )
	{
		// UDP
		return 2;
	}
	else if( code == 1 )
	{
		// ICMP
		return 3;
	}
	else
	{
		return -1;
	}
}

int handle_packet(uint8_t* packet)
{
	/* Create a flow if its not there */
}

