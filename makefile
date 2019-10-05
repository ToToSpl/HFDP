pcap main.c:
	gcc -o pcap main.c HFDP.c udp_sockets.c file_interpreter.c -lpcap