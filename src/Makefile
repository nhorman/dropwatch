all: dropwatch
CFLAGS+=-c

dropwatch: *.o 
	gcc -g -lreadline -lnl -o dropwatch main.o

%.o: %.c
	gcc $(CFLAGS) $<
clean:
	rm -f dropwatch *.o

