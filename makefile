all:	main.o netflow.o packet_handler.o
	gcc -g -o netflow flow_cache.o netflow.o packet_handler.o main.o -lpcap
main.o:	main.c common.h
	gcc -g -c main.c
netflow.o: netflow.c netflow.h
	gcc -g -c netflow.c
flow_cache.o: flow_cache.c flow_cache.h
	gcc -g -c flowcache.c
packet_handler.o: packet_handler.c packet_handler.h
	gcc -g -c packet_handler.c
clean:	
	rm *.o
