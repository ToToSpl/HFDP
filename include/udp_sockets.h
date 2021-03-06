#ifndef UDP_SOCKETS

#define UDP_SOCKETS

#include <sys/types.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <netinet/in.h> 

/*
 *             ----------UDP SOCKETS INFORMATION-----------
 * 
 * Whole HFDP protocol is based on a idea, that it can resend UDP protocol.
 * Because of that udp sockets play a big role in this programme,
 * although HFDP could be theoreticly deployed on some device like esp32 where
 * there is no need of UDP.
 * 
 */ 

//this struct holds info about given udp socket
typedef struct{
    struct sockaddr_in myAddr, deviceAddr;
    int port, buffer_size, sockfd;
    u_int32_t last_packet_size;
    u_int8_t* buffer;
    u_int8_t serOrCli;
}udp_socket;


//generates udp server
int udp_init(udp_socket* udp_info, char* servOrClient);

//listen for udp packets and put recieved data into buffer
void udp_listener(udp_socket* udp_info);

//send buffer info by given udp port
void udp_send(udp_socket* udp_info, int lenght);

#endif