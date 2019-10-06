#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "HFDP.h"
#include "file_interpreter.h"
#include "udp_sockets.h"

void generate_headers(char *file_name, SOCKET_LIST* socket_list){
    
    FILE *fp;
    fp = fopen(file_name,"r");

    char *line = NULL;
    size_t len = 0;

    int numOflines = 0;
    int nread;
    while((nread = getline(&line, &len, fp)) != -1) numOflines++;
    socket_list->number_of_sockets = numOflines;
    fseek(fp,0,SEEK_SET);

    socket_list->sockets = malloc(sizeof(*socket_list->sockets)*numOflines);

    for(int i = 0; i < numOflines; i++){

        socket_list->sockets[i] = malloc(sizeof(SOCKET_INFO));
        socket_list->sockets[i]->mac = malloc(sizeof(int) * 6);

        nread = getline(&line, &len, fp);

        sscanf(line, "%d %s %x %x %x %x %x %x %s %d",
            &socket_list->sockets[i]->socket,
            socket_list->sockets[i]->fec,
            &socket_list->sockets[i]->mac[0],
            &socket_list->sockets[i]->mac[1],
            &socket_list->sockets[i]->mac[2],
            &socket_list->sockets[i]->mac[3],
            &socket_list->sockets[i]->mac[4],
            &socket_list->sockets[i]->mac[5], 
            socket_list->sockets[i]->direction, 
            &socket_list->sockets[i]->buffer);
    }
}

void generate_macs(char *file_name, MAC_LIST *mac_list){
    
    FILE *fp;
    fp = fopen(file_name,"r");

    char *line = NULL;
    size_t len = 0;

    int nread;

    int numOflines = 0;

    while((nread = getline(&line, &len, fp)) != -1) numOflines++;
    fseek(fp,0,SEEK_SET);

    mac_list->num_of_macs = numOflines;    
    mac_list->macs = malloc(sizeof(*mac_list->macs)*numOflines);

    for(int j = 0; j < numOflines; j++){

        mac_list->macs[j] = malloc(sizeof(u_int8_t)*6);

        nread = getline(&line, &len, fp);

        sscanf(line, "%x %x %x %x %x %x",
        &mac_list->macs[j][0],&mac_list->macs[j][1],&mac_list->macs[j][2],&mac_list->macs[j][3],&mac_list->macs[j][4],&mac_list->macs[j][5]);

        if(nread > 18){
            mac_list->device_id = j;
        }
    }
}