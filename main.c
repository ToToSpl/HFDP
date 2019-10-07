#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include "HFDP.h"

#define SENDING

#define MAC_OFFSET 10
#define MAC_SIZE 6

#define CUT_RADIOTAP_SIZE 18
//because during sendig packet is cut of timestamp and something more we cant just add size of radiotap and offset
#define PATTERN_OFFSET CUT_RADIOTAP_SIZE + 16

//Device settings
#define TX_ID 0
#define RX_ID 1


int printDevices(char *error_buffer);
void callback(u_int8_t *user, const struct pcap_pkthdr *h, const u_int8_t *bytes);

static u_int8_t mac_ids[2][MAC_SIZE]={
    {0x00, 0xC0, 0xCA, 0x97, 0xC0, 0x49},
    {0x00, 0xC0, 0xCA, 0x97, 0xEE, 0xFD}
};

static u_int8_t dumpBuf[] = "twoj stary najebany a twoja stara zapierdala";

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

int main(int argc, char **argv){
    char error_buffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 ip_raw;
    bpf_u_int32 subnet_mask_raw;
    int lookup_return_code;

    if(argc == 1){
        printf("Please type name of the wanted wifi card during launching.\nList of devices:\n");
        printDevices(error_buffer);
        return -1;
    }

    pcap_t *device;
 
    device = pcap_open_live(argv[1], 1000, 1, 0, error_buffer);
    if (device == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], error_buffer);
		return -1;
	}

    lookup_return_code = pcap_setnonblock(device,1,error_buffer);
    if(lookup_return_code != 0){
        printf("Error in setting nonblocking mode! %s\n",error_buffer);
        return -1;
    }

    #ifdef SENDING

    printf("Begin to send packets...\n");

    //Add correct mac address
    memcpy(u8aIeeeHeader_beacon + MAC_OFFSET, mac_ids[TX_ID], sizeof(u_int8_t)*MAC_SIZE);
    memcpy(u8aIeeeHeader_beacon + MAC_OFFSET + MAC_SIZE, mac_ids[RX_ID], sizeof(u_int8_t)*MAC_SIZE);

    HFDP *header = malloc(sizeof(HFDP));
    header->id = 0x01; header->flags = 0x00; header->rssi = 0x01; header->size = (u_int16_t)sizeof(dumpBuf);
    header->data = malloc(header->size);
    memcpy(header->data, dumpBuf, header->size);

    packet *testpacket = malloc(sizeof(packet));
    generatePacket(testpacket, u8aRadiotapHeader, u8aIeeeHeader_beacon, header);

    for(int i = 0; i < testpacket->size; i++){
        printf("%X ",testpacket->buff[i]);
    }
    printf("\n");

    while(1){

        lookup_return_code = pcap_inject(device,testpacket->buff,testpacket->size);
        if(lookup_return_code != testpacket->size){
            printf("Error during sending! Closing...\n");
            return -1;
        }
        printf("packet send. Size of the packet: %i\n",lookup_return_code);
        usleep(5e5);
    }

    #endif

    printf("Launching reading loop...\n");
    lookup_return_code = pcap_loop(device, -1, callback, "main");
        
    return 0;
}



int printDevices(char *error_buffer){
    pcap_if_t *devices, *temp;

    if(pcap_findalldevs(&devices, error_buffer) == -1){
        printf("ERROR FINDING DEVICES: %s\n", error_buffer);
        return -1;
    }
    
    for(temp = devices; temp; temp = temp->next){
        printf("%s\n", temp->name);
    }
    pcap_freealldevs(devices);
    pcap_freealldevs(temp);
    return 0;
}

void callback(u_int8_t *user, const struct pcap_pkthdr *h, const u_int8_t *bytes){

    //any packet that interest us cant be shorter than this
    if(h->len < CUT_RADIOTAP_SIZE + IEEE_SIZE) return;

    for(int i = 0; i < MAC_SIZE; i++){
        if(bytes[PATTERN_OFFSET + i] != mac_ids[RX_ID][i]) return;
    }

    //here goes func from rxtx

    printf("SIZE OF PACKET: %i\n",h->len);

    HFDP *container = malloc(sizeof(HFDP));
    readHFDP(bytes,container);

    printf("packet ID: %i\n",container->id);
    printf("packet FLAGS: %i\n",container->flags);
    printf("packet RSSI: %i\n",container->rssi);
    printf("packet SIZE: %i\n",container->size);

    #if __x86_64__
        printf("TimeStamp: %lus %lums\n\n", h->ts.tv_sec, h->ts.tv_usec);
    #else
        printf("TimeStamp: %us %ums\n\n", h->ts.tv_sec, h->ts.tv_usec);
    #endif

    for(int i = 0; i < container->size; i++) printf("%c",container->data[i]);
    printf("\n\n");

    free(container->data);
    free(container);
}