import socket
import time

UDP_IP = "127.0.0.1"
UDP_PORT = 10000
MESSAGE = "twoj stary najebany a twoja stara zapierdala"

print("UDP target IP:", UDP_IP)
print("UDP target port:", UDP_PORT)
print("message:", MESSAGE)

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
while True:
    sock.sendto(MESSAGE.encode('utf-8'), (UDP_IP, UDP_PORT))
    time.sleep(0.5)