#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#include "file_interpreter.h"
#include "rxtx.h"
#include "HFDP.h"
#include "udp_sockets.h"

#define DEBUG

void initTransmission(char* udp_file, char* mac_file, SOCKET_LIST* socket_list, MAC_LIST* mac_list){

    //first use file_interpreter functions to partialy populate lists
    generate_headers(udp_file, socket_list);
    //mac list is finished
    generate_macs(mac_file, mac_list);

    //now we need to generate udp socket for each HFDP socket
    for(int i = 0; i < socket_list->number_of_sockets; i++){
        //assuming that socket is ok for this moment
        socket_list->sockets[i]->isCorrupted = 0;

        udp_socket *ptr = malloc(sizeof(udp_socket));

        ptr->buffer_size = socket_list->sockets[i]->buffer;
        ptr->buffer = malloc(ptr->buffer_size);

        ptr->port = socket_list->sockets[i]->socket;
        
        if(udp_init(ptr) < 0){
            printf("Error occured on creating socket id: %i\nThis socket will be ignored\n",i);
            socket_list->sockets[i]->isCorrupted=1;
            break;
        }

        socket_list->sockets[i]->udp = ptr;
    }

}

void sendLocalToAir(SOCKET_LIST* socket_list, MAC_LIST* mac_list, int socketID, pcap_t *device, u_int8_t* globalRSSI){

    SOCKET_INFO *sock_ptr = socket_list->sockets[socketID];

    //first we have to recieve data from UDP
    //WARNING! this is blocking function, it will be stuck untill something will be recieved
    udp_listener(sock_ptr->udp);

    //making local header for safety
    u_int8_t* local_u8aIeeeHeader_beacon = malloc(sizeof(u8aIeeeHeader_beacon));
    memcpy(local_u8aIeeeHeader_beacon, u8aIeeeHeader_beacon, sizeof(u8aIeeeHeader_beacon));

    //now let us create a HFDP struct and populate it with known info
    HFDP* hfdp_struct = malloc(sizeof(HFDP));
    hfdp_struct->id = socketID;
    hfdp_struct->rssi = ++*globalRSSI;
    hfdp_struct->size = sock_ptr->udp->last_packet_size;
    memcpy(hfdp_struct->reMAC, sock_ptr->mac, MAC_SIZE);

    //setting FEC flag
    if(sock_ptr->fec == "FEC") hfdp_struct->flags |= ENCODED;

    //now we have to check where our packet is supposed to go
    int targetID = mac_list->device_id;
    for(int i = 0; i < mac_list->num_of_macs; i++){
        for(int j = 0; j < MAC_SIZE; j++){
            if(mac_list->macs[i][j] != sock_ptr->mac[j]) goto next;
        }
        targetID = i;
        break;
        next:
    }

    //check if the packet is one device higher or lower i.e will packet have to be resend
    if(targetID-1 == mac_list->device_id || targetID+1 == mac_list->device_id){
        //packet will not have to be resend, setting flag is not needed
    }else{
        hfdp_struct->flags |= RESEND;
    }

    //setting correct mac address
    if(targetID > mac_list->device_id){
        memcpy(local_u8aIeeeHeader_beacon + MAC_OFFSET, mac_list->macs[mac_list->device_id + 1], MAC_SIZE);
    }else if(targetID < mac_list->device_id){
        memcpy(local_u8aIeeeHeader_beacon + MAC_OFFSET, mac_list->macs[mac_list->device_id - 1], MAC_SIZE);
    }
    memcpy(local_u8aIeeeHeader_beacon + MAC_OFFSET + MAC_SIZE, mac_list->macs[mac_list->device_id], MAC_SIZE);

    //copying data to hfdp struct
    hfdp_struct->data = malloc(hfdp_struct->size);
    memcpy(hfdp_struct->data, sock_ptr->udp->buffer, hfdp_struct->size);

    packet *finalPacket = malloc(sizeof(packet));
    generatePacket(finalPacket, u8aRadiotapHeader, local_u8aIeeeHeader_beacon, hfdp_struct);

    #ifdef DEBUG
    for(int i = 0; i < finalPacket->size; i++){
        printf("%X ",finalPacket->buff[i]);
    }
    printf("\n");
    #endif

    //finally sending packet
    int lookup_return_code = pcap_inject(device,finalPacket->buff,finalPacket->size);
        if(lookup_return_code != finalPacket->size){
            printf("Error during sending!\n");
            sock_ptr->isCorrupted = 1;
        }

    //NOW WE HAVE TO CLEAN ALLOCATED MEMORY
    //REMEMBER ABOUT BUFFERS INSIDE STRUCTS

    //cleaning finalPacket
    free(finalPacket->buff); free(finalPacket);
    //cleaning hfdp_struct
    free(hfdp_struct->data); free(hfdp_struct);
    //cleaning sock_ptr
    free(sock_ptr);
    //cleaning local header
    free(local_u8aIeeeHeader_beacon);
}

void sendAirToLocal(SOCKET_LIST* socket_list, MAC_LIST* mac_list, HFDP* phfdp, pcap_t *device, u_int8_t* buffer, int bufLen){

    //first let us see if the package should be resend
    if(phfdp->flags & RESEND){
        //package should be resend

        //making local header for safety
        u_int8_t* local_u8aIeeeHeader_beacon = malloc(sizeof(u8aIeeeHeader_beacon));
        memcpy(local_u8aIeeeHeader_beacon, u8aIeeeHeader_beacon, sizeof(u8aIeeeHeader_beacon));

        //we need to find where to send the package
        int targetID = -1;
        for(int i = 0; i < mac_list->num_of_macs; i++){
            for(int j = 0; j < MAC_SIZE; j++){
                if(mac_list->macs[i][j] != phfdp->reMAC[j]) goto next;
            }
            targetID = i;
            break;
            next:
        }

        if(targetID == -1){
            //this MAC is from some other familly breaking function
            free(local_u8aIeeeHeader_beacon);
            return;
        }

        //check if the packet is one device higher or lower i.e will packet have to be resend
        if(targetID-1 == mac_list->device_id || targetID+1 == mac_list->device_id){
            //packet will not have to be resend again, setting flag to zero
            phfdp->flags ^= RESEND;
        }

        //setting correct mac address
        if(targetID > mac_list->device_id){
            memcpy(local_u8aIeeeHeader_beacon + MAC_OFFSET, mac_list->macs[mac_list->device_id + 1], MAC_SIZE);
        }else if(targetID < mac_list->device_id){
            memcpy(local_u8aIeeeHeader_beacon + MAC_OFFSET, mac_list->macs[mac_list->device_id - 1], MAC_SIZE);
        }

        packet *finalPacket = malloc(sizeof(packet));
        generatePacket(finalPacket, u8aRadiotapHeader, local_u8aIeeeHeader_beacon, phfdp);

        #ifdef DEBUG
        for(int i = 0; i < finalPacket->size; i++){
            printf("%X ",finalPacket->buff[i]);
        }
        printf("\n");
        #endif

        //finally sending packet
        int lookup_return_code = pcap_inject(device,finalPacket->buff,finalPacket->size);
            if(lookup_return_code != finalPacket->size){
                printf("Error during resending!\n");
            }

        //cleaning memory
        free(local_u8aIeeeHeader_beacon);
        free(finalPacket->buff);
        free(finalPacket);
        //thats all in this case
        return;
    }

    //if no resend, packet should be send to udp
    SOCKET_INFO* sockptr = socket_list->sockets[phfdp->id];
    sockptr->udp->buffer = malloc(phfdp->size);
    memcpy(sockptr->udp->buffer, phfdp->data, phfdp->size);

    udp_send(sockptr->udp, phfdp->size);

    //now cleaning memory
    free(sockptr->udp->buffer);
    free(sockptr);

}