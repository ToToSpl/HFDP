


LIBRARIES = -lpcap -lpthread
INCLUDEDIR = -I ./include

EXE = pcap

all:
	gcc src/*.c -o $(EXE) $(LIBRARIES) $(INLUDEDIR)
clean:
	-rm $(EXE)
