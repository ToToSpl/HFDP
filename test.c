#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "file_interpreter.h"


int main(){
    
    MAC_LIST *mac_list = malloc(sizeof(MAC_LIST));
    generate_macs("mac_list.txt",mac_list);

    printf("NUMBER OF MACS: %i\nID OF THE CURRENT DEVICE: %i\n",mac_list->num_of_macs,mac_list->device_id);

    for(int i = 0; i < mac_list->num_of_macs; i++){
        printf("MAC NUMBER %i: ",i);
        for(int j = 0; j < 6; j++) printf("%X ",mac_list->macs[i][j]);
        printf("\n");
    }

    printf("\n\n");

    SOCKET_LIST *socket_list =malloc(sizeof(SOCKET_LIST));
    generate_headers("udp_config.txt", socket_list);


    for(int i = 0; i < socket_list->number_of_sockets; i++){
        printf("PORT SOCKET: %i\nBUFFER SIZE: %i\n",socket_list->sockets[i]->socket, socket_list->sockets[i]->buffer);
        printf("FEC MODE: %s\nDIRECTION MODE: %s\n",socket_list->sockets[i]->fec, socket_list->sockets[i]->direction);
        printf("TARGET MAC: "); for(int j=0;j<6;j++) printf("%X ",socket_list->sockets[i]->mac[j]); printf("\n\n");
    }


    return 0;
}