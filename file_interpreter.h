

/*
 * Quick info how config files work
 * udp_config file holds the information how each udp port should be set
 * each line of the config is next udp server the ID of each one increase by one and the first has ID 0
 * divided by spaces we have these options: socket FEC/NO_FEC ReMAC INPUT/OUTPUT/BIDIRECTIONAL BUFFER_SIZE CLIENT/SERVER 
 * ReMAC is a six byte MAC address of the device to which packet should go packet will be resend according to mac list till it reach it source
 * 
 * mac_list has list of macs beggining from the first device till last in hiearchy
 * this setup is used to resend packets from the ground station to the target plane via plane in the middle
 * 
 *current device is set by writing THIS after the mac address of the given device in the list
 */

#ifndef FILE_INT

#define FILE_INT

#include <sys/types.h>
#include "HFDP.h"
#include "udp_sockets.h"


typedef struct{
    int num_of_macs, device_id;
    u_int8_t **macs;
}MAC_LIST;

typedef struct{
    int socket, buffer, isCorrupted;
    u_int8_t *mac;
    char fec[10], direction[10], servOrClient[10];
    udp_socket *udp;
}SOCKET_INFO;

typedef struct{
    int number_of_sockets;
    SOCKET_INFO **sockets;
}SOCKET_LIST;

//generates HFDP packet headers based on file return number of headers in list 
void generate_headers(char *file_name, SOCKET_LIST* socket_list);

//generates list of macs based on a file and return mac of the device
void generate_macs(char *file_name, MAC_LIST *mac_list);



#endif