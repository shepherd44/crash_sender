CC = g++
objects = main.o pmanager.o probe.o inetproto.o mylist.o nicinfo.o pcapsocket.o 
inc_pcap = -lpcap -I/home/hjm/project/probe/include/
options = -W -g 

LD_LIBRARY_PATH := ./lib

probed : $(objects)  
	$(CC) $(options) -o probed $(objects) $(inc_pcap)

main.o : probe.h pmanager.h
	$(CC) $(options) -c main.cc

pmanager.o : pmanager.h
	$(CC) $(options) -c pmanager.cc 

probe.o : probe.h
	$(CC) $(options) -c probe.cc

mylist.o : mylist.h
	$(CC) $(options) -c mylist.cc

inetproto.o : inetproto.h
	$(CC) $(options) -c inetproto.cc

nicinfo.o : nicinfo.h
	$(CC) $(options) -c nicinfo.cc -std=c++0x

pcapsocket.o : pcapsocket.h
	$(CC) -c pcapsocket.cc

.PHONY : clean
clean : 
	rm $(objects)
	rm probed
