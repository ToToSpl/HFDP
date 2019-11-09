#include "../include/rxtx.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#include "../include/file_interpreter.h"
#include "../include/HFDP.h"
#include "../include/udp_sockets.h"

//#define DEBUGTX
//#define DEBUGRX

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
        ptr->port = socket_list->sockets[i]->socket;
        
        if(udp_init(ptr, socket_list->sockets[i]->servOrClient) < 0){
            printf("Error occured on creating socket id: %i\nThis socket will be ignored\n",i);
            socket_list->sockets[i]->isCorrupted=1;
            break;
        }

        socket_list->sockets[i]->rxFrac = NULL;
        socket_list->sockets[i]->udp = ptr;
        socket_list->sockets[i]->rssiRX = 0;
        socket_list->sockets[i]->rssiTX = 0;
    }
}

void sendLocalToAir(SOCKET_LIST* socket_list, MAC_LIST* mac_list, int socketID, pcap_t *device){

    SOCKET_INFO *sock_ptr = socket_list->sockets[socketID];

    //first we have to recieve data from UDP
    //WARNING! this is blocking function, it will be stuck untill something will be recieved
    udp_listener(sock_ptr->udp);

    //making local header for safety
    u_int8_t* local_u8aIeeeHeader_beacon = malloc(IEEE_SIZE);
    memcpy(local_u8aIeeeHeader_beacon, u8aIeeeHeader_beacon, IEEE_SIZE);

    //now let us create a HFDP struct and populate it with known info
    HFDP* hfdp_struct = malloc(sizeof(HFDP));
    hfdp_struct->id = socketID;
    hfdp_struct->size = sock_ptr->udp->last_packet_size;
    hfdp_struct->reMAC = malloc(MAC_SIZE);
    hfdp_struct->flags = 0x00;

    memcpy(hfdp_struct->reMAC, sock_ptr->mac, MAC_SIZE);

    //setting FEC flag
    if(sock_ptr->fec[0] == 'F') hfdp_struct->flags |= ENCODED;

    //now we have to check where our packet is supposed to go
    int targetID = mac_list->device_id;
    for(int i = 0; i < mac_list->num_of_macs; i++){
        for(int j = 0; j < MAC_SIZE; j++){
            if(mac_list->macs[i][j] != sock_ptr->mac[j]) goto next;
        }
        targetID = i;
        break;
        next:
        continue;
    }

    //check if the packet is one device higher or lower i.e will packet have to be resend
    if(targetID-1 == mac_list->device_id || targetID+1 == mac_list->device_id){
        //packet will not have to be resend, setting flag is not needed
    }else{
        hfdp_struct->flags |= RESEND;
    }

    //setting correct mac address
    if(targetID > mac_list->device_id){
        memcpy(local_u8aIeeeHeader_beacon + MAC_OFFSET + MAC_SIZE, mac_list->macs[mac_list->device_id + 1], MAC_SIZE);
    }else if(targetID < mac_list->device_id){
        memcpy(local_u8aIeeeHeader_beacon + MAC_OFFSET + MAC_SIZE, mac_list->macs[mac_list->device_id - 1], MAC_SIZE);
    }
    memcpy(local_u8aIeeeHeader_beacon + MAC_OFFSET, mac_list->macs[mac_list->device_id], MAC_SIZE);

    //pointer for buffer that goes to pcap
    packet *finalPacket = malloc(sizeof(packet));
    hfdp_struct->data = malloc(MAX_SINGLE_PACKET_SIZE);
    u_int32_t send_num = 0;

    //If udp packet is bigger than max hfdp packet size we have to send it in parts
    if(sock_ptr->udp->last_packet_size > MAX_SINGLE_PACKET_SIZE){
        //first set in the flag so we know that the packet is cutted
        hfdp_struct->size = MAX_SINGLE_PACKET_SIZE;
        hfdp_struct->flags |= FRACTURED_PACKET;
    }   
        
    //now sending packets until next packet is smaller than max packet size
    while((sock_ptr->udp->last_packet_size - send_num) > MAX_SINGLE_PACKET_SIZE){
        hfdp_struct->flags |= FRACTURED_PACKET;
        //copying data to hfdp struct
        memcpy(hfdp_struct->data, sock_ptr->udp->buffer + send_num, MAX_SINGLE_PACKET_SIZE);
        hfdp_struct->rssi = ++sock_ptr->rssiTX;
        generatePacket(finalPacket, u8aRadiotapHeader, local_u8aIeeeHeader_beacon, hfdp_struct);
        #ifdef DEBUGTX
        for(int i = 0; i < finalPacket->size; i++){
            printf("%X ",finalPacket->buff[i]);
        }
        printf("\n\n");
        #endif

        //sending given packet
        for(int resend = 0; resend < sock_ptr->sendAmount; resend++){

            int lookup_return_code = pcap_inject(device,finalPacket->buff,finalPacket->size);
            if(lookup_return_code != finalPacket->size){
                printf("Error during sending! size of packet: %i\n",lookup_return_code);
                printf("Size should be: %i\n", finalPacket->size);
                sock_ptr->isCorrupted = 1;
            }
        }
        
        //increasing send_num
        send_num += MAX_SINGLE_PACKET_SIZE;
    }

    //now setting that this is the last package, or if its normal
    if(hfdp_struct->flags & FRACTURED_PACKET) hfdp_struct->flags |= PACKET_END;
    hfdp_struct->size = sock_ptr->udp->last_packet_size - send_num;
    //copying data to hfdp struct
    memcpy(hfdp_struct->data, sock_ptr->udp->buffer + send_num, sock_ptr->udp->last_packet_size - send_num);
    hfdp_struct->rssi = ++sock_ptr->rssiTX;
    generatePacket(finalPacket, u8aRadiotapHeader, local_u8aIeeeHeader_beacon, hfdp_struct);
    //sending final packet
    for(int resend = 0; resend < sock_ptr->sendAmount; resend++){
        int lookup_return_code = pcap_inject(device,finalPacket->buff,finalPacket->size);
        if(lookup_return_code != finalPacket->size){
            printf("Error during sending! size of packet: %i\n",lookup_return_code);
            printf("Size should be: %i\n", finalPacket->size);
            sock_ptr->isCorrupted = 1;
        }
    }
    
    //NOW WE HAVE TO CLEAN ALLOCATED MEMORY
    //REMEMBER ABOUT BUFFERS INSIDE STRUCTS
    
    //cleaning finalPacket
    free(finalPacket->buff); free(finalPacket);
    //cleaning hfdp_struct
    free(hfdp_struct->data); free(hfdp_struct->reMAC); free(hfdp_struct);
    //cleaning local header
    free(local_u8aIeeeHeader_beacon);
}

void sendAirToLocal(SOCKET_LIST* socket_list, MAC_LIST* mac_list, HFDP* phfdp, pcap_t *device){

    SOCKET_INFO* sockptr = socket_list->sockets[phfdp->id];

    //checking if given packet was recieved already
    if(sockptr->rssiRX == phfdp->rssi) return;
    else sockptr->rssiRX = phfdp->rssi;

    //first let us see if the package should be resend
    if(phfdp->flags & RESEND){
        //package should be resend
        printf("packet resend\n");
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
            continue;
        }

        if(targetID == -1){
            //this MAC is from some other familly breaking function
            free(local_u8aIeeeHeader_beacon);
            return;
        }

        //check if the packet is one device higher or lower i.e. will packet have to be resend
        if(targetID-1 == mac_list->device_id || targetID+1 == mac_list->device_id){
            //packet will not have to be resend again, setting flag to zero
            phfdp->flags ^= RESEND;
        }

        //setting correct mac address
        if(targetID > mac_list->device_id){
            memcpy(local_u8aIeeeHeader_beacon + MAC_OFFSET + MAC_SIZE, mac_list->macs[mac_list->device_id + 1], MAC_SIZE);
        }else if(targetID < mac_list->device_id){
            memcpy(local_u8aIeeeHeader_beacon + MAC_OFFSET + MAC_SIZE, mac_list->macs[mac_list->device_id - 1], MAC_SIZE);
        }

        packet *finalPacket = malloc(sizeof(packet));
        generatePacket(finalPacket, u8aRadiotapHeader, local_u8aIeeeHeader_beacon, phfdp);

        #ifdef DEBUGRX
        for(int i = 0; i < finalPacket->size; i++)
            printf("%X ",finalPacket->buff[i]);
        printf("\n");
        #endif

        //finally sending packet
        for(int resend = 0; resend < sockptr->sendAmount; resend++){
            int lookup_return_code = pcap_inject(device,finalPacket->buff,finalPacket->size);
            if(lookup_return_code != finalPacket->size){
                printf("Error during resending!\n");
            }
        }
        
        //cleaning memory
        free(local_u8aIeeeHeader_beacon);
        free(finalPacket->buff);
        free(finalPacket);
        //thats all in this case
        return;
    }
    //if no resend, packet should be send to udp
    

    //logic for manipulating fragmented packets
    if(phfdp->flags & FRACTURED_PACKET){
        if(sockptr->rxFrac == NULL){
            //this is the beginning of the packet
            //setting max size of the buff
            //sockptr->udp->buffer = malloc(sockptr->buffer);
            sockptr->rxFrac = sockptr->udp->buffer;
        }
        
        //safety system when we've lost PACKET_END package and next one is fractured
        if(sockptr->rxFrac + phfdp->size - sockptr->udp->buffer > sockptr->buffer){
            udp_send(sockptr->udp, sockptr->buffer);
            sockptr->rxFrac = NULL;  
            return;
        }

        //putting to buffer
        memcpy(sockptr->rxFrac, phfdp->data, phfdp->size);
        sockptr->rxFrac += phfdp->size;


        if(phfdp->flags & PACKET_END){
            //thats the last packet we can send udp and close buffer

            #ifdef DEBUGRX
            for(int i = 0; i < sockptr->rxFrac - sockptr->udp->buffer; i++)
                printf("%X ",sockptr->udp->buffer[i]);
            printf("\n\n");
            #endif
            
            udp_send(sockptr->udp, sockptr->rxFrac - sockptr->udp->buffer);

            sockptr->rxFrac = NULL;
        }
    }else{
        
        //if rxFrac is not null that means that we have lost end packet part
        if(sockptr->rxFrac != NULL){
            //LOST PACKET SOMETHING HAS TO BE TOLD IN THE FUTURE!!
            printf("Lost packet!\n");
            sockptr->rxFrac = NULL;
        }

        memcpy(sockptr->udp->buffer, phfdp->data, phfdp->size);
        udp_send(sockptr->udp, phfdp->size);

        #ifdef DEBUGRX
        for(int i = 0; i < phfdp->size; i++)
            printf("%X ", phfdp->data[i]);
        printf("\n\n");
        #endif
    }
}