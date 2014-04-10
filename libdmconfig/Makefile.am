## libdmconfig Makefile.am

AM_CFLAGS = -g -funit-at-a-time \
	-I$(top_srcdir)/include/compat \
        -I$(top_srcdir)

BUILT_SOURCES = codes.h
CLEANFILES = codes.h

libdmconfigincdir = $(includedir)/libdmconfig
libdmconfiginc_HEADERS = dmmsg.h dmconfig.h dmcontext.h codes.h \
			 dm_dmclient_rpc_impl.h \
			 dm_dmclient_rpc_skel.h \
			 dm_dmconfig_rpc_stub.h

dmconfigdatadir = $(datadir)/dmd
dmconfigdata_DATA = dmconfig.xml

lib_LTLIBRARIES = libdmconfig.la libdm_dmconfig.la libdm_dmclient.la

libdmconfig_la_SOURCES = \
		dmmsg.c \
		dmconfig.c \
		dmcontext.c

libdm_dmconfig_la_SOURCES = \
		dm_dmconfig_rpc_skel.c \
		dm_dmclient_rpc_stub.c

libdm_dmclient_la_SOURCES = \
		dm_dmclient_rpc_skel.c \
		dm_dmclient_rpc_impl.c \
		dm_dmconfig_rpc_stub.c

if LIBDMCONFIG_DEBUG
libdmconfig_la_SOURCES += debug.c
endif
libdmconfig_la_LIBADD = $(top_builddir)/utils/libdmutils.la
libdm_dmconfig_la_LIBADD = libdmconfig.la
libdm_dmclient_la_LIBADD = libdmconfig.la

codes.h : dictionary.xsl dmconfig.xml
	@XSLTPROC@ -o $@ $^
