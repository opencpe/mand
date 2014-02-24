noinst_PROGRAMS = dm_tests

AM_CFLAGS = -DWITH_SOAPDEFS_H -D_GNU_SOURCE -g -std=gnu99  -I$(srcdir)/.. -I.. -I$(top_srcdir)/include/compat

dm_tests_SOURCES = dm_tests.c
dm_tests_LDADD = ../libdmstore.la