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
	
	// Creating socket file descriptor 
	if ( (udp_info->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
		perror("socket creation failed"); 
		return -1;
	}

    udp_info->buffer = malloc(udp_info->buffer_size);
	
	memset(&udp_info->servaddr, 0, sizeof(udp_info->servaddr)); 
	memset(&udp_info->cliaddr, 0, sizeof(udp_info->cliaddr)); 
	
	// Filling server information 
	udp_info->servaddr.sin_family = AF_INET; // IPv4 
	udp_info->servaddr.sin_addr.s_addr = INADDR_ANY; 
	udp_info->servaddr.sin_port = htons(udp_info->port);
	
	if(servOrClient == "SERVER"){
		// Bind the socket with the server address 
		if ( bind(udp_info->sockfd, (const struct sockaddr *)&udp_info->servaddr, 
				sizeof(udp_info->servaddr)) < 0 ) 
		{ 
			perror("bind failed"); 
			return -1;
		}
	}else{
		udp_info->cliaddr.sin_addr.s_addr = INADDR_ANY;
		udp_info->cliaddr.sin_port = htons(udp_info->port);
	}
	return 1;
}

void udp_listener(udp_socket* udp_info) { 

	int len = sizeof(udp_info->cliaddr); 
    int n = -1;
	
	while(n == -1){
		n = recvfrom(udp_info->sockfd, udp_info->buffer, udp_info->buffer_size, 
			0, ( struct sockaddr *) &udp_info->cliaddr, 
			&len);
	}
	udp_info->last_packet_size = n;
}

void udp_send(udp_socket* udp_info, int lenght){
    
    sendto(udp_info->sockfd, udp_info->buffer, lenght,  
        0, (const struct sockaddr *) &udp_info->cliaddr, 
            sizeof(udp_info->cliaddr)); 
}
