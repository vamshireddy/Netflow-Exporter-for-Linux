all:	main.o netflow.o
	gcc -o netflow main.o netflow.o
	
main.o:	main.c common.h
	gcc -c main.c

netflow.o: netflow.c netflow.h
	gcc -c netflow.c
clean:	
	rm *.o
