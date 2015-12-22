CC = g++
objects = main.o pmanager.o probe.o inetproto.o mylist.o sniffer.o nic.o pmcprotocol.o #pcapsocket.o
inc_pcap = -lpcap -I/home/hjm/project/probe/include/
inc_pthread = -lpthread
options = -W -g 

LD_LIBRARY_PATH := ./lib

probed : $(objects)  
	$(CC) $(options) -o probed $(objects) $(inc_pcap) $(inc_pthread)

main.o : probe.h pmanager.h sniffer.h
	$(CC) $(options) -c main.cc

pmanager.o : pmanager.h
	$(CC) $(options) -c pmanager.cc -std=c++0x 

probe.o : probe.h sniffer.h
	$(CC) $(options) -c probe.cc

mylist.o : mylist.h
	$(CC) $(options) -c mylist.cc

inetproto.o : inetproto.h
	$(CC) $(options) -c inetproto.cc

#pcapsocket.o : pcapsocket.h
#	$(CC) -c pcapsocket.cc

nic.o : nic.h
	$(CC) $(options) -c nic.cc

sniffer.o : sniffer.h pmcprotocol.h probe.h pmanager.h
	$(CC) $(options) -c sniffer.cc

pmcprotocol.o: pmcprotocol.h nic.h
	$(CC) $(options) -c pmcprotocol.cc

.PHONY : clean
clean : 
	rm $(objects)
	rm probed
