all: send_arp

send_arp: main.o send_arp.o
	g++ -o send_arp main.o send_arp.o -lpcap

send_arp.o: send_arp.cpp
	g++ -c -o send_arp.o send_arp.cpp

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f send_arp *.o
