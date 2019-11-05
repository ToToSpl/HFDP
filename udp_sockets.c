#include "udp_sockets.h"

#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

int udp_init(udp_socket* udp_info, char* servOrClient){

	udp_info->serOrCli = servOrClient[0];
	
	// Creating socket file descriptor 
	if ( (udp_info->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
		perror("socket creation failed"); 
		return -1;
	}

    udp_info->buffer = malloc(udp_info->buffer_size);
	
	memset(&udp_info->myAddr, 0, sizeof(udp_info->myAddr)); 
	memset(&udp_info->deviceAddr, 0, sizeof(udp_info->deviceAddr)); 
	
	// Filling server information 
	udp_info->myAddr.sin_family = AF_INET; // IPv4 
	udp_info->deviceAddr.sin_family = AF_INET; // IPv4 
	udp_info->myAddr.sin_addr.s_addr = INADDR_ANY;
	udp_info->deviceAddr.sin_addr.s_addr = INADDR_ANY;

	udp_info->myAddr.sin_port = htons(udp_info->port);

	if(udp_info->serOrCli == 'S'){
			
		//printf("SERVER MODE\n");

		// Bind the socket with the server address 
		if ( bind(udp_info->sockfd, (const struct sockaddr *)&udp_info->myAddr, 
				sizeof(udp_info->myAddr)) < 0 ) 
		{ 
			perror("bind failed"); 
			return -1;
		}
	}else{
		//udp_info->deviceAddr.sin_port = htons(udp_info->port);
	}
	return 1;
}

void udp_listener(udp_socket* udp_info) { 

	int len = sizeof(udp_info->deviceAddr); 
    int n = -1;
	
	while(n == -1){
		n = recvfrom(udp_info->sockfd, udp_info->buffer, udp_info->buffer_size, 
			0, ( struct sockaddr *) &udp_info->deviceAddr, 
			&len);
	}
	udp_info->last_packet_size = (u_int32_t)n;
}

void udp_send(udp_socket* udp_info, int lenght){

    if(udp_info->serOrCli == 'S'){
		//printf("sending to client port: %i\n",udp_info->deviceAddr.sin_port);
		sendto(udp_info->sockfd, udp_info->buffer, lenght,  
        0, (const struct sockaddr *) &udp_info->deviceAddr, 
            sizeof(udp_info->deviceAddr)); 
	}else{
		sendto(udp_info->sockfd, udp_info->buffer, lenght,  
        0, (const struct sockaddr *) &udp_info->myAddr, 
            sizeof(udp_info->myAddr));
	}
}
