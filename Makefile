LDLIBS=-lpcap

all: airodump

main.o: wireless.h beacon_frame.h radiotap.h main.h main.cpp

radiotap.o: radiotap.h radiotap.cpp

beacon_frame.o: beacon_frame.h beacon_frame.cpp

wireless.o: wireless.h wireless.cpp

airodump: main.o radiotap.o beacon_frame.o wireless.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -pthread

clean:
	rm -f airodump *.o
