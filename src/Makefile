all: dropwatch

CPPFLAGS += -D_GNU_SOURCE
CFLAGS += -g -Wall -Werror $(shell pkg-config --cflags libnl-3.0)
LDLIBS += -lbfd -lreadline -lnl-3 -lnl-genl-3

OBJFILES := main.o lookup.o\
	 lookup_bfd.o lookup_kas.o

dropwatch: $(OBJFILES) 
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	$(RM) dropwatch *.o
