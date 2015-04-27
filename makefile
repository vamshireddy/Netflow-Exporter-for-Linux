all:	main.o netflow.o packet_handler.o
	gcc -g -o netflow netflow.o packet_handler.o main.o -lpcap
main.o:	main.c common.h
	gcc -g -c main.c
netflow.o: netflow.c netflow.h
	gcc -g -c netflow.c
packet_handler.o: packet_handler.c packet_handler.h
	gcc -g -c packet_handler.c
clean:	
	rm *.o
