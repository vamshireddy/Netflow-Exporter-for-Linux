#include "common.h"
/*
	This file has structures and routines to manipulate the packet */
/*
 * Structure of an internet header, naked of options.
 */
struct ip_hdr
{
    	uint8_t ip_vhl;				/* version and header length */
    	uint8_t ip_tos;				/* type of service */
    	uint16_t ip_len;			/* total length */
    	uint16_t ip_id;				/* identification */
    	uint16_t ip_off;			/* fragment offset field */
	#define	IP_RF 0x8000			/* reserved fragment flag */
	#define	IP_DF 0x4000			/* dont fragment flag */
	#define	IP_MF 0x2000			/* more fragments flag */
	#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    	uint8_t ip_ttl;				/* time to live */
    	uint8_t ip_p;				/* protocol */
    	uint16_t ip_sum;			/* checksum */
    	uint32_t ip_src, ip_dst;		/* source and dest address */
} __attribute__ ((packed)) ;
typedef struct ip_hdr ip_hdr_t;

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */

typedef struct tcp_hdr {
        uint16_t tcp_sport;	               	/* source port */
        uint16_t tcp_dport;     	        /* destination port */
        uint32_t tcp_seq;              	   	/* sequence number */
        uint32_t tcp_ack;                 	/* acknowledgement number */
        uint8_t  tcp_offx2;               	/* data offset, rsvd */
	#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
        uint8_t  tcp_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        uint16_t tcp_win;                 	/* window */
        uint16_t tcp_sum;                 	/* checksum */
        uint16_t tcp_urp;                 	/* urgent pointer */
}tcp_hdr_t;

/* UDP Packet */

typedef struct udp_hdr {
	uint16_t udp_sport;
	uint16_t udp_dport;
   	uint16_t udp_len;
    	uint16_t udp_sum;
}udp_hdr_t;

/* Ethernet Header */

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

typedef struct ether_hdr {
	uint8_t ether_dhost[ETHER_ADDR_LEN]; 	/* Destination host address */
	uint8_t ether_shost[ETHER_ADDR_LEN]; 	/* Source host address */
	uint16_t ether_type; 	/* IP? ARP? RARP? etc */
}ether_hdr_t;

/*
	This is the callback function. It is called when a packet comes or leaves the interface
*/
void handle_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet);
