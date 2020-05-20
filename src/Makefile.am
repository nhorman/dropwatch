
bin_PROGRAMS = dropwatch dwdump

AM_CFLAGS = -g -Wall -Werror $(LIBNL3_CFLAGS) $(LIBNLG3_CFLAGS) $(READLINE_CFLAGS)
AM_LDFLAGS = $(LIBNL3_LIBS) $(LIBNLG3_LIBS) $(READLINE_LIBS) -lpcap
AM_CPPFLAGS = -D_GNU_SOURCE

dropwatch_SOURCES = main.c lookup.c lookup_kas.c
dwdump_SOURCES = dwdump.c

if USE_BFD
dropwatch_SOURCES += lookup_bfd.c
AM_LDFLAGS += -lbfd
endif
