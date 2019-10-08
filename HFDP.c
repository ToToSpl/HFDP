#include "HFDP.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

void readHFDP(u_int8_t *buffer, HFDP* container){
    container->id = buffer[HFDP_START_PLACE  + ID_OFFSET];
    container->flags = buffer[HFDP_START_PLACE + FLAGS_OFFSET];
    container->rssi = buffer[HFDP_START_PLACE + RSSI_OFFSET];

    if(container->flags & RESEND != 0x00){
        container->reMAC = buffer + HFDP_START_PLACE + REMAC_OFFSET;
    }else{
        container->reMAC = NULL;
    }
    
    container->size = buffer[HFDP_START_PLACE + SIZE_OFFSET] + (buffer[HFDP_START_PLACE + SIZE_OFFSET + 1] << 8);

    container->data = malloc(container->size);
    memcpy(container->data, buffer + HFDP_START_PLACE + DATA_OFFSET, container->size);
}

void generatePacket(packet* whole_packet, u_int8_t *radiotap, u_int8_t *ieec, HFDP *container){

    whole_packet->buff = malloc(RADIOTAP_SIZE + IEEE_SIZE + HEADER_SIZE + container->size);

    u_int8_t *ptr = whole_packet->buff;
    memcpy(ptr,radiotap,RADIOTAP_SIZE);
    ptr+=RADIOTAP_SIZE;

    memcpy(ptr,ieec,IEEE_SIZE);
    ptr+=IEEE_SIZE;

    memcpy(ptr,&container->id,ID_SIZE);
    ptr+=ID_SIZE;

    memcpy(ptr,&container->flags,FLAGS_SIZE);
    ptr+=FLAGS_SIZE;

    memcpy(ptr,&container->rssi,RSSI_SIZE);
    ptr+=RSSI_SIZE;

    if(container->flags & RESEND) memcpy(ptr,&container->reMAC,REMAC_SIZE);
    else memset(ptr, 0, REMAC_SIZE);
    ptr+=REMAC_SIZE;

    memcpy(ptr,&container->size,SIZE_SIZE);
    ptr+=SIZE_SIZE;

    memcpy(ptr,container->data,container->size);
    ptr+=container->size;

    whole_packet->size = ptr - whole_packet->buff;    
}