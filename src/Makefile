all: dropwatch
CFLAGS+=-c -g -D_GNU_SOURCE -Wall -Werror
LDFLAGS=-lbfd -lreadline -lnl
OBJFILES := main.o lookup.o\
	 lookup_bfd.o lookup_kas.o

dropwatch: $(OBJFILES) 
	gcc -g -o dropwatch $(OBJFILES) $(LDFLAGS) 

%.o: %.c
	gcc $(CFLAGS) $<
clean:
	rm -f dropwatch *.o

