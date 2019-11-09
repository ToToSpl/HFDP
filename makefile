


LIBRARIES = -lpcap -lpthread
INCLUDEDIR = -I ./include

EXE = pcap

all:
	gcc $(LIBRARIES) $(LIBDIR) $(INCLUDEDIR) src/*.c -o $(EXE)
clean:
	-rm $(EXE)