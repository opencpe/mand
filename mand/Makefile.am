# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

AM_CFLAGS = -g -funit-at-a-time \
	-I$(top_srcdir) \
	-I$(top_srcdir)/include/compat

SUBDIRS = snmp .

sbin_PROGRAMS = dmctrl mand

noinst_LTLIBRARIES = libdm.la libdmstore.la
#noinst_BIN = dm_store

dmctrl_SOURCES = dmctrl.c
dmctrl_LDADD = $(top_builddir)/utils/libdmutils.la \
		  $(top_builddir)/libdmconfig/libdmconfig.la

libdmstore_la_SOURCES = dm_store.c dm_index.c dm_notify.c dm_cache.c \
			dm_serialize.c dm_deserialize.c dm_signature.c \
			dm_strings.c dm_action.c \
			dm_cfgsessions.c dm_cfgversion.c \
			dm_cfg_bkrst.c dm_validate.c \
			p_table.c p_table_stubs.c dm_assert.c
libdmstore_la_LIBADD = $(LIBM) $(DMLIBS) $(top_builddir)/utils/libdmutils.la

libdm_la_SOURCES = \
		dm_dmconfig.c \
		process.c \
		inet_helper.c \
		dm_luaif.c

BUILT_SOURCES = p_table.c p_table.h p_table_stubs.c
CLEANFILES = p_table.c p_table.h p_table_stubs.c

DISTCLEANFILES = *xml *.log *~

libdm_la_LIBADD = $(LIBM) $(DMLIBS) $(NVRAMLIBS) \
			libdmstore.la \
			$(top_builddir)/utils/libdmutils.la \
			$(top_builddir)/libdmconfig/libdmconfig.la

mand_SOURCES = mand.c dm.c \
		 dm_action_table.c

if AGENTX
libdm_la_LIBADD += snmp/libsnmp.la
endif

if NET_SNMP
mand_SOURCES += net-snmpd.c
endif

mand_LDADD = libdm.la

p_table.c p_table.h p_table_stubs.c: $(top_srcdir)/tablegen/tokenizer.pl $(top_srcdir)/tablegen/DM-Tab.csv
	$(top_srcdir)/tablegen/tokenizer.pl $(top_srcdir)/tablegen/DM-Tab.csv


impl_list.csv:
	grep "VAR.*InternetGatewayDevice\." $(srcdir)/*.[ch] | sed -e"s/\([^:]*\).*VAR:\s*\(.*\)\*\/.*/\1,\2/g" > impl_list.csv
