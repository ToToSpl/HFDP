#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h> 

#include "udp_sockets.h"
#include "file_interpreter.h"
#include "HFDP.h"
#include <pcap.h>
 

void udp_init(udp_socket* udp_info){
	
	// Creating socket file descriptor 
	if ( (udp_info->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
		perror("socket creation failed"); 
		exit(EXIT_FAILURE); 
	}

    udp_info->buffer = malloc(udp_info->buffer_size);
	
	memset(&udp_info->servaddr, 0, sizeof(udp_info->servaddr)); 
	memset(&udp_info->cliaddr, 0, sizeof(udp_info->cliaddr)); 
	
	// Filling server information 
	udp_info->servaddr.sin_family = AF_INET; // IPv4 
	udp_info->servaddr.sin_addr.s_addr = INADDR_ANY; 
	udp_info->servaddr.sin_port = htons(udp_info->port); 
	
	// Bind the socket with the server address 
	if ( bind(udp_info->sockfd, (const struct sockaddr *)&udp_info->servaddr, 
			sizeof(udp_info->servaddr)) < 0 ) 
	{ 
		perror("bind failed"); 
		exit(EXIT_FAILURE); 
	}
}

void udp_listener(udp_socket* udp_info, u_int8_t* buffer) { 

	int len = sizeof(udp_info->cliaddr); 
    int n = -1; 
	
	while(n){
		n = recvfrom(udp_info->sockfd, udp_info->buffer, udp_info->buffer_size, 
			0, ( struct sockaddr *) &udp_info->cliaddr, 
			&len);
        /*
		if(n > 0){
            //DO STUFF HERE
			printf("size: %i\n",n);
			for(int i=0; i < n; i++) printf("%X ", buffer[i]);
			printf("\n\n");
		}
        */
	}
}

void udp_send(udp_socket* udp_info, int lenght){
    
    sendto(udp_info->sockfd, udp_info->buffer, lenght,  
        0, (const struct sockaddr *) &udp_info->cliaddr, 
            sizeof(udp_info->cliaddr)); 
}
