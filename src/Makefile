
all: dropwatch


dropwatch: *.o 
	gcc -g -D__GNUC__ -lreadline -lnl -o dropwatch main.o

%.o: %.c
	gcc -g -c $<
clean:
	rm -f dropwatch *.o

