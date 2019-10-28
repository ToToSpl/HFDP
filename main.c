#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include "HFDP.h"
#include "file_interpreter.h"
#include "rxtx.h"

#define SENDING

#define CUT_RADIOTAP_SIZE 18
//because during sendig packet is cut of timestamp and something more we cant just add size of radiotap and offset
#define PATTERN_OFFSET CUT_RADIOTAP_SIZE + 16

MAC_LIST *global_mac_list;
SOCKET_LIST *global_socket_list;
pcap_t *global_device;
HFDP *prevContainer;

int printDevices(char *error_buffer);
void callback(u_int8_t *user, const struct pcap_pkthdr *h, const u_int8_t *bytes);


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
 
    global_device = pcap_open_live(argv[1], 1000, 1, 0, error_buffer);
    if (global_device == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], error_buffer);
		return -1;
	}

    lookup_return_code = pcap_setnonblock(global_device,1,error_buffer);
    if(lookup_return_code != 0){
        printf("Error in setting nonblocking mode! %s\n",error_buffer);
        return -1;
    }

    global_mac_list = malloc(sizeof(MAC_LIST));
    global_socket_list =malloc(sizeof(SOCKET_LIST));
    u_int8_t* globalRSSI = malloc(sizeof(u_int8_t));

    initTransmission("udp_config.txt", "mac_list.txt", global_socket_list, global_mac_list);

    printf("Init success\n");

    #ifdef SENDING

    while(1){
        sendLocalToAir(global_socket_list, global_mac_list, 0, global_device, globalRSSI);
    }

    #endif

    prevContainer = malloc(sizeof(HFDP));
    printf("Launching reading loop...\n");
    lookup_return_code = pcap_loop(global_device, -1, callback, "main");
        
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
        if(bytes[PATTERN_OFFSET + i] != global_mac_list->macs[global_mac_list->device_id][i]) return;
    }

    HFDP *container = malloc(sizeof(HFDP));
    readHFDP((u_int8_t*)bytes,container);

    //if this is resend of the package, ignore it
    if(container->id == prevContainer->id && container->rssi == prevContainer->rssi) return;
    else memcpy(prevContainer, container, sizeof(HFDP));

    //here goes func from rxtx
    sendAirToLocal(global_socket_list, global_mac_list, container, global_device);

    /*
    printf("SIZE OF PACKET: %i\n",h->len);
    printf("packet ID: %i\n",container->id);
    printf("packet FLAGS: %i\n",container->flags);
    printf("packet RSSI: %i\n",container->rssi);
    printf("packet SIZE: %i\n",container->size);
    for(int i = 0; i < container->size; i++) printf("%X ",container->data[i]);
    printf("\n\n");
    */

    free(container->data);
    free(container);
}