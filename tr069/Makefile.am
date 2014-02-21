#
# (c) 2009 Travelping GmbH
#

AM_CFLAGS = -DWITH_SOAPDEFS_H -g -funit-at-a-time \
	-I$(top_srcdir) \
	-I$(top_srcdir)/tools \
	-I$(top_srcdir)/libradius \
	-I$(top_srcdir)/include/compat

SVN_VERSION := $(shell svnversion -n $(srcdir))
SVN_NUMVER := $(shell svnversion -n $(srcdir) | awk '/[^:]+:.+/ {split($$1, v, ":"); print strtonum(v[2])} /^[^:]+$$/ {print strtonum($$1)}')

SUBDIRS = snmp .

sbin_PROGRAMS = tr069ctrl tr069d
pkginclude_HEADERS = connmark.h

noinst_LTLIBRARIES = libtr069.la libdmstore.la
#noinst_BIN = tr069_store

#bin_PROGRAMS = tr069d
#		tr.c tr069_download.c tr069_table.c tr069_setvalue.c tr069_getvalue.c

tr069ctrl_SOURCES = tr069ctrl.c
tr069ctrl_LDADD = $(top_builddir)/utils/libdmutils.la \
		  $(top_builddir)/libdmconfig/libdmconfig.la

libdmstore_la_SOURCES = tr069_store.c tr069_index.c tr069_notify.c tr069_cache.c \
			tr069_serialize.c tr069_deserialize.c tr069_signature.c \
			tr069_strings.c \
			tr069_action.c \
			tr069_cfgsessions.c tr069_cfgversion.c \
			tr069_cfg_bkrst.c tr069_validate.c \
			p_table.c p_table_stubs.c dm_assert.c
libdmstore_la_LIBADD = $(LIBM) $(TR069LIBS) $(top_builddir)/utils/libdmutils.la

libtr069_la_SOURCES = \
		soapbuild.c \
		tr069_download.c tr069_values.c \
		cwmp_paramattrs.c \
		cwmp_paramnames.c \
		tr069_dmconfig.c \
		tr069_fkts.c inet_helper.c \
		tr069_event_queue.c tr069_request_queue.c \
		tr069_luaif.c \
		svn_version.c svn_version.h

BUILT_SOURCES = soapC.c soapClient.c soapServer.c soapH.h svn_version.c svn_version.h p_table.c p_table.h p_table_stubs.c
CLEANFILES = \
		soapH.h soapStub.h soapC.cpp soapC.c \
		soapClient.cpp soapClient.c  soapClientLib.c \
		soapServer.cpp soapServerLib.c soapServer.c \
		soap*Proxy.h \
		svn_version.c svn_version.h

DISTCLEANFILES = *.wsdl *.xsd *.xml *.nsmap *.log *~

libtr069_la_LIBADD = $(LIBM) $(TR069LIBS) $(NVRAMLIBS) \
			libdmstore.la \
			$(top_builddir)/utils/libdmutils.la \
			$(top_builddir)/libdmconfig/libdmconfig.la

tr069d_SOURCES = tr069d.c tr.c tr069_firmware.c tr069_ipkg.c reboot.c process.c \
		 ifup.c if_device.c l3forward.c proxy.c hw_defaults.c uevent.c \
		 if_ppp.c if_madwifi.c if_switch.c dnsmasq.c \
		 session.c radius.c client.c lng.c ippool.c dhcp.c \
		 net_sched.c if_vlan.c if_bridge.c if_ofswitch.c board_support.c \
		 tr069_ping.c tr069_trace.c tr069_capture.c tr069_action_table.c \
		 cares-ev.c tr069_async_resolve.c tr069_autogen.c \
		 monitor.c iso3166.c

if DHCP_INTERNAL
tr069d_SOURCES += dhcp_internal.c 
endif

if DHCP_DHCPD
tr069d_SOURCES += dhcp_dhcpd.c
endif

if SCG_FW
tr069d_SOURCES += firewall_scg.c
endif

if LNG_FW
tr069d_SOURCES += firewall_lng.c
endif

if AGENTX
libtr069_la_LIBADD += snmp/libsnmp.la
endif

if ATM
tr069d_SOURCES += br2684ctl.c
endif

if BRCM43XX
tr069d_SOURCES += bcm47xx_support.c if_brcm43xx.c
endif

if BCM63XX
tr069d_SOURCES += bcm63xx_support.c bcm63xx_adsl.c bcm63xx_atm.c
endif

if AR7
tr069d_SOURCES += ar7_support.c if_marvell6060.c
endif

if NET_SNMP
tr069d_SOURCES += net-snmpd.c
endif

if PURESNMPD
tr069d_SOURCES += puresnmpd.c
endif

tr069d_LDADD = libtr069.la \
		$(top_builddir)/tools/libmtd.la \
		$(top_builddir)/libradius/libradius.la \
		$(top_builddir)/utils/libdmutils.la

soapC.c soapClient.c soapServer.c soapH.h: $(srcdir)/tr.h
	$(GSOAP) -cLwx $(srcdir)/tr.h

p_table.c p_table.h p_table_stubs.c: $(top_srcdir)/tablegen/tokenizer.pl $(top_srcdir)/tablegen/TR069-Tab.csv
	$(top_srcdir)/tablegen/tokenizer.pl $(top_srcdir)/tablegen/TR069-Tab.csv


impl_list.csv:
	grep "VAR.*InternetGatewayDevice\." $(srcdir)/*.[ch] | sed -e"s/\([^:]*\).*VAR:\s*\(.*\)\*\/.*/\1,\2/g" > impl_list.csv

##
## on every build, record the working copy revision string
##
svn_version.c: .version-${SVN_NUMVER}
	( echo "#include \"svn_version.h\""; echo "const char *svn_version(void) { static const char* SVN_Version = \"$(SVN_VERSION)\"; return SVN_Version; }" ) > svn_version.c

svn_version.h: .version-${SVN_NUMVER}
	$(SED) -e"s/@@SVN_NUMVER@@/$(SVN_NUMVER)/" $(srcdir)/svn_version.h.in > svn_version.h

.version-${SVN_NUMVER}:
	touch $@
