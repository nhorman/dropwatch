
all: dropwatch


dropwatch: *.o 
	gcc -g -lreadline -o dropwatch main.o

%.o: %.c
	gcc -g -c $<
clean:
	rm -f dropwatch *.o

