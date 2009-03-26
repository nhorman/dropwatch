all: dropwatch
CFLAGS+=-c

dropwatch: main.o lookup.o 
	gcc -g -lreadline -lnl -o dropwatch main.o lookup.o

%.o: %.c
	gcc $(CFLAGS) $<
clean:
	rm -f dropwatch *.o

