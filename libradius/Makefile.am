AM_CFLAGS = -std=gnu99 -g

# noinst_PROGRAMS = radtest

# radtest_SOURCES = radtest.c
# radtest_LDADD = libradius.la

noinst_LTLIBRARIES = libradius.la

libradius_la_SOURCES = radlib.c radlib_compat.c
libradius_la_LIBADD = -lpolarssl -lev

noinst_HEADERS = radlib_private.h

pkginclude_HEADERS = radlib.h radlib_compat.h radlib_vs.h

EXTRA_DIST = CREDITS libradius.3 radius.conf.5

