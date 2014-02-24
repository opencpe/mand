#
# (c) 2009 Travelping GmbH
#

AM_CFLAGS = -g -funit-at-a-time \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include/compat

SUBDIRS = snmp .

sbin_PROGRAMS = tr069ctrl tr069d

noinst_LTLIBRARIES = libtr069.la libdmstore.la
#noinst_BIN = tr069_store

tr069ctrl_SOURCES = tr069ctrl.c
tr069ctrl_LDADD = $(top_builddir)/utils/libdmutils.la \
		  $(top_builddir)/libdmconfig/libdmconfig.la

libdmstore_la_SOURCES = tr069_store.c tr069_index.c tr069_notify.c tr069_cache.c \
			tr069_serialize.c tr069_deserialize.c tr069_signature.c \
			tr069_strings.c tr069_action.c \
			tr069_cfgsessions.c tr069_cfgversion.c \
			tr069_cfg_bkrst.c tr069_validate.c \
			p_table.c p_table_stubs.c dm_assert.c
libdmstore_la_LIBADD = $(LIBM) $(TR069LIBS) $(top_builddir)/utils/libdmutils.la

libtr069_la_SOURCES = \
		tr069_dmconfig.c \
		process.c \
		inet_helper.c \
		tr069_luaif.c

BUILT_SOURCES = p_table.c p_table.h p_table_stubs.c
CLEANFILES = p_table.c p_table.h p_table_stubs.c

DISTCLEANFILES = *xml *.log *~

libtr069_la_LIBADD = $(LIBM) $(TR069LIBS) $(NVRAMLIBS) \
			libdmstore.la \
			$(top_builddir)/utils/libdmutils.la \
			$(top_builddir)/libdmconfig/libdmconfig.la

tr069d_SOURCES = tr069d.c tr.c \
		 tr069_action_table.c

if AGENTX
libtr069_la_LIBADD += snmp/libsnmp.la
endif

if NET_SNMP
tr069d_SOURCES += net-snmpd.c
endif

tr069d_LDADD = libtr069.la

p_table.c p_table.h p_table_stubs.c: $(top_srcdir)/tablegen/tokenizer.pl $(top_srcdir)/tablegen/TR069-Tab.csv
	$(top_srcdir)/tablegen/tokenizer.pl $(top_srcdir)/tablegen/TR069-Tab.csv


impl_list.csv:
	grep "VAR.*InternetGatewayDevice\." $(srcdir)/*.[ch] | sed -e"s/\([^:]*\).*VAR:\s*\(.*\)\*\/.*/\1,\2/g" > impl_list.csv
