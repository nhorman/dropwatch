# SPDX-License-Identifier: GPL-2.0-or-later
#
bin_PROGRAMS = dropwatch dwdump

AM_CFLAGS = -g -Wall -Werror $(LIBNL3_CFLAGS) $(LIBNLG3_CFLAGS) $(READLINE_CFLAGS)
AM_LDFLAGS =
ALL_LIBS = $(LIBNL3_LIBS) $(LIBNLG3_LIBS) $(READLINE_LIBS) $(LIBPCAP_LIBS)
dropwatch_LDADD = $(ALL_LIBS)
dwdump_LDADD = $(ALL_LIBS)
AM_CPPFLAGS = -D_GNU_SOURCE

dropwatch_SOURCES = main.c lookup.c lookup_kas.c
dwdump_SOURCES = dwdump.c

if USE_BFD
dropwatch_SOURCES += lookup_bfd.c
dropwatch_LDADD += -lbfd
endif
