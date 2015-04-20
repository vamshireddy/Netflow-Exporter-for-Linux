all:	main.o netflow.o
	gcc -o netflow main.o netflow.o

main.o:	main.c
	gcc -c main.c

netflow.o: netflow.c
	gcc -c netflow.c

clean:	
	rm *.o
