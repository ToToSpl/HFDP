#include <sys/types.h>

#ifndef HFDP_H

#define HFDP_H

/*
 * HFDP - HIGH FLYERS DATA PROTOCOL
 * This protocol is designed to send udp packets via wifi modules set in monitor mode
 * udp packets can be encrypted with FEC (forward error correction) for better chance of recieving
 * packets also send one byte RSSI signal to test if there are lost packets
 * HFDP can also send heartbeat just to keep communication alive
 * packets can be resend to other device using ReMAC or Beam option
 * ReMAC is a MAC address to which packet is supossed to get.
 * Packet will be resend to next device set in mac_config.txt file
 * 
 * 
 * structure of the packet:
 * +--------------+----------+--+-----+----+-----+----+----+
 * |RadioTapHeader|IEECHeader|ID|FLAGS|RSSI|ReMAC|SIZE|DATA|
 * +--------------+----------+--+-----+----+-----+----+----+
 * 
*/


//BIG SIZES
#define HFDP_START_PLACE 42
#define IEEE_SIZE 24
#define RADIOTAP_SIZE 25

//OFFSETS
#define ID_OFFSET 0
#define FLAGS_OFFSET 1
#define RSSI_OFFSET 2
#define REMAC_OFFSET 3
#define SIZE_OFFSET 9
#define DATA_OFFSET 11

//DATA SIZES
#define HEADER_SIZE 11
#define ID_SIZE 1
#define FLAGS_SIZE 1
#define RSSI_SIZE 1
#define REMAC_SIZE 6
#define SIZE_SIZE 2

//FLAGS
#define HEARTBEAT 0x01
#define ISFEC 0x02
#define BEAM 0x04
#define RESEND 0x08
#define ENCODED 0x10
#define SEND_TO_SLAVE 0x20
#define FRACTURED_PACKET 0x40
#define PACKET_END 0x80


typedef struct
{
    u_int8_t id, flags, rssi;
    u_int8_t *reMAC;
    u_int16_t size;
    u_int8_t *data;
}HFDP;

typedef struct
{
    int size;
    u_int8_t *buff;
}packet;


void readHFDP(u_int8_t *buffer, HFDP* container);
void generatePacket(packet* whole_packet, u_int8_t *radiotap, u_int8_t *ieec, HFDP *container);


#endif