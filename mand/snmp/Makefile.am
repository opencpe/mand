AM_CFLAGS=-DWITH_SOAPDEFS_H -funit-at-a-time -Wall -std=gnu99 \
        -I$(top_srcdir) \
        -I$(top_srcdir)/mand \
        -I$(top_srcdir)/include/compat \
        -I..

if AGENTX

noinst_LTLIBRARIES = libsnmp.la

libsnmp_la_LDFLAGS = $(SNMP_LIBS)
libsnmp_la_SOURCES = radiusAuthServ.c			\
		     radiusAccServ.c			\
		     radiusAuthClient.c			\
		     radiusAccClient.c			\
		     radiusAuthServerExtTable.c		\
		     radiusAccServerExtTable.c		\
		     radiusAuthClientExtTable.c		\
		     radiusAccClientExtTable.c		\
		     zoneAccessClassTable.c

endif
