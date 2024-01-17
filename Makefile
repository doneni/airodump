LDLIBS=-lpcap

all: airodump


main.o: beacon_frame.h radiotap.h main.cpp

radiotap.o: radiotap.h radiotap.cpp

beacon_frame.o: beacon_frame.h beacon_frame.cpp

airodump: main.o radiotap.o beacon_frame.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o
