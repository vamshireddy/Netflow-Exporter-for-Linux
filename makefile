all:	main.o netflow.o packet_handler.o
	gcc -o netflow main.o netflow.o packet_handler.o
	
main.o:	main.c common.h
	gcc -c main.c

netflow.o: netflow.c netflow.h
	gcc -c netflow.c
packet_handler.o: packet_handler.c packet_handler.h
	gcc -c packet_handler.c
clean:	
	rm *.o
