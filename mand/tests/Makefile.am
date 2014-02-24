noinst_PROGRAMS = tr069_tests

AM_CFLAGS = -DWITH_SOAPDEFS_H -D_GNU_SOURCE -g -std=gnu99  -I$(srcdir)/.. -I.. -I$(top_srcdir)/include/compat

tr069_tests_SOURCES = tr069_tests.c
tr069_tests_LDADD = ../libdmstore.la