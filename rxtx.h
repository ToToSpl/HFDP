#ifndef RXTX

#define RXTX

#include "udp_sockets.h"
#include "file_interpreter.h"
#include "HFDP.h"
#include <pcap.h>

/*
 * MAIN FUNCTIONS RESPONSIBLE FOR TRANSMITING AND RECIEVING 
 * 
 * 
 *
 */

//current working header for alfa awus036nh

//header taken from Packetspammer by Andy Green <andy@warmcat.com>
//i treat this as magic spell
u_int8_t u8aRadiotapHeader[] = {
	0x00, 0x00, // <-- radiotap version
	0x19, 0x00, // <- radiotap header length
	0x6f, 0x08, 0x00, 0x00, // <-- bitmap
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp
	0x00, // <-- flags
	0x0B, // <-- rate 11*500kbs
	0x71, 0x09, 0xc0, 0x00, // <-- channel
	0xde, // <-- antsignal
	0x00, // <-- antnoise
	0x01, // <-- antenna
};

u_int8_t u8aIeeeHeader_beacon[] = {
	0x08, 0x01, 0x00, 0x00, // frame control field (2 bytes), duration (2 bytes)
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,// 1st byte of IEEE802.11 RA (mac) must be 0xff or something odd, otherwise strange things happen. second byte is the port (will be overwritten later)
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
	0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // mac
	0x10, 0x86, // IEEE802.11 seqnum, (will be overwritten later by Atheros firmware/wifi chip)
};

#define MAC_OFFSET 10
#define MAC_SIZE 6

//initialize udp sockets based on text files and populates lists
void initTransmission(char* udp_file, char* mac_file, SOCKET_LIST* socket_list, MAC_LIST* mac_list);

//sends single packet from local socket to HFDP
void sendLocalToAir(SOCKET_LIST* socket_list, MAC_LIST* mac_list, int socketID, pcap_t *device, u_int8_t* globalRSSI);

//this function is sitting in main in callback func
void sendAirToLocal(SOCKET_LIST* socket_list, MAC_LIST* mac_list, HFDP* phfdp, pcap_t *device, u_int8_t* buffer, int bufLen);


#endif