
bin_PROGRAMS = dropwatch

AM_CFLAGS = -g -Wall -Werror $(LIBNL3_CFLAGS) $(READLINE_CFLAGS)
AM_LDFLAGS = $(LIBNL3_LIBS) -lnl-genl-3 -lbfd $(READLINE_LIBS)
AM_CPPFLAGS = -D_GNU_SOURCE

dropwatch_SOURCES = main.c lookup_bfd.c lookup.c lookup_kas.c
