LDLIBS=-lpcap

all: airodump


main.o: mac.h beacon_frame.h ieee80211_radiotap.h main.cpp

ieee80211_radiotap.o: ieee80211_radiotap.h ieee80211_radiotap.cpp

beacon_frame.o: mac.h beacon_frame.h beacon_frame.cpp

mac.o: mac.h mac.cpp

airodump: main.o ieee80211_radiotap.o beacon_frame.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o
