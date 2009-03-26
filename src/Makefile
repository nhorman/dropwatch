all: dropwatch
CFLAGS+=-c -g
LDFLAGS=-lbfd -lreadline -lnl

dropwatch: main.o lookup.o 
	gcc -g -o dropwatch main.o lookup.o $(LDFLAGS) 

%.o: %.c
	gcc $(CFLAGS) $<
clean:
	rm -f dropwatch *.o

