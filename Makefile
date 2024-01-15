LDLIBS=-lpcap

all: airodump


main.o: main.cpp

airodump: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o
