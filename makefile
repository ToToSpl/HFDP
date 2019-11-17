


LIBRARIES = -lpcap -lpthread
INCLUDEDIR = -I ./include

EXE = hfdp

all:
	gcc src/*.c -o $(EXE) $(LIBRARIES) $(INLUDEDIR)
clean:
	-rm $(EXE)
