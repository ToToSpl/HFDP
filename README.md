# HIGH FLYERS DATA PROTOCOL (HFDP)



High Flyers Data Protocol is a software inspired by [WifiBroadcast](https://github.com/rodizio1/ez-wifibroadcast/wiki).
Using Pcap library and of-the-shelf wifi modules (like [this](https://www.alfa.com.tw/service_1_detail/5.htm)) we send any udp data peer-to-peer.
This software was developed on ubuntu and rasbian, requiers just pcaplib-dev and pthread!

HFDP include many options usefull for autonomous vehicles:

  - Can send data from any local UDP client/server (like telemetry or video)
  - Two modules doesn't need to have bidirectional communication
  - Each packet can be pass via man-in-the-middle (you can have two planes and one can act as a retransmitter)
  - Any wifi module that supports packet injection and monitor mode can be used

# How to use it?

Firstly you have to edit two text files udp_config.txt and mac_list.txt
In the first one write data in this manner:
 - each line is a new socket
 - udp socket (for example 14550)
 - if you want to use FEC or not (FEC / NO_FEC) not implemented! just wirte NO_FEC
 - mac address of your target device each 8bit hex value is separated with spaces
 - INPUT/OUTPUT/BIDIRECTIONAL depending on type of this connection
 - size of the UDP buffer max can be 8196
 - SERVER/CLIENT depending if your software will be a udp client or server (so for example mavproxy makes a client on 14550 so HFDP has to be a server)
 - how many times single packet should be send

So our final line will look like:
```
14550 NO_FEC FF FF FF FF FF FF BIDIRECTIONAL 2048 SERVER 1
```
You can make up to 255 hfdp sockets in this manner.

In mac_list.txt you have to write a hierarchy of your devices. So for example you could write mac address of your ground station then closer plane and finally further airplane, so packet send to second plane will go through first one. To specify to the program which device he is write THIS after a mac.
Example would look like this:

```
00 00 00 00 00 00 THIS
AA AA AA AA AA AA
FF FF FF FF FF FF
```

Mac addresses doesn't need to be real they can be just random number you set.


After that you have to set up your wifi module first in terminal type:

```sh
iwconfig
```

A list of devices will pop-up, find the name of the module you want to use and type:

```sh
sudo ifconfig <module_name> down
sudo iwconfig <module_name> mode monitor
sudo iwconfig <module_name> channel <1-13 channel you want to use>
sudo ifconfig <module_name> up
```

Finally go to your copy of this repository type make and run pcap!



License
----

GNU GPLv3

