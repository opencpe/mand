## libdmconfig Makefile.am

AM_CFLAGS = -g -funit-at-a-time \
        -I$(top_srcdir)

BUILT_SOURCES = codes.h
CLEANFILES = codes.h

libdmconfigincdir = $(includedir)/libdmconfig
libdmconfiginc_HEADERS = dmmsg.h dmconfig.h codes.h

dmconfigdatadir = $(datadir)/dmd
dmconfigdata_DATA = dmconfig.xml

luadmlibdir = $(lualibdir)
luadmdatadir = $(lualibdir)

lib_LTLIBRARIES = libdmconfig.la

if LIBDMCONFIG_LUAWRAPPER

luadmlib_LTLIBRARIES = libluadmconfig.la
luadmdata_DATA = extensivedump.out

CLEANFILES += extensivedump.out

endif

libdmconfig_la_SOURCES = dmmsg.c dmconfig.c
if LIBDMCONFIG_DEBUG
libdmconfig_la_SOURCES += debug.c
endif
libdmconfig_la_LIBADD = $(top_builddir)/utils/libdmutils.la

libluadmconfig_la_SOURCES = luawrapper.c
libluadmconfig_la_LIBADD = libdmconfig.la $(top_builddir)/utils/libdmutils.la

extensivedump.out : extensivedump.lua
	@LUAC@ @LUACFLAGS@ -o $@ $^

codes.h : dictionary.xsl dmconfig.xml
	@XSLTPROC@ -o $@ $^

if LIBDMCONFIG_LUAWRAPPER

install-data-hook:
	mv $(DESTDIR)$(lualibdir)/extensivedump.out $(DESTDIR)$(lualibdir)/extensivedump.lua

endif

