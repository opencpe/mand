dnl ##
dnl ##  PROLOG
dnl ##

dnl #   standard Autoconf prolog

AC_PREREQ(2.59)

AC_INIT(tr069, [1.0])
AC_CONFIG_SRCDIR(tr069/tr.c)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(1.9)

AC_SRCDIR_PREFIX(srcdir_prefix)
AC_HEADLINE(dnl
TPOSS TR069 Config Agent, dnl
[Copyright (c) 2004,2005 Andreas Schultz <aschultz@warp10.net>])
AC_CONFIG_PARAM(config.param)
AM_CONFIG_HEADER(config.h)
AC_PREFIX_DEFAULT(/usr)
AC_PLATFORM(PLATFORM)


dnl ##
dnl ##  BUILD TOOLS
dnl ##

AC_MSG_PART(Build Tools)

AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CPP
AM_PROG_CC_C_O
AC_CHECK_PROG(LUAC, luac, luac)
AC_CHECK_PROG(LUAC, luac5.1, luac5.1)
AC_CHECK_PROG(RENAME, rename, rename)
AC_PROG_INSTALL
AC_SET_MAKE
AC_CHECK_DEBUGGING
AC_CHECK_PROG(XSLTPROC, xsltproc, xsltproc)
if test x$XSLTPROC = x; then
   AC_MSG_ERROR([Couldn't find xsltproc (XSLT processor)])
fi

AC_MSG_PART(Configure libtool)
AM_PROG_LIBTOOL
AC_MSG_PART(Configure gSOAP)
AC_PATH_PROG(GSOAP, soapcpp2)
if test -z "$GSOAP"; then
   AC_MSG_ERROR([please install gsoap - http://www.cs.fsu.edu/~engelen/soap.html
])
fi

dnl ##
dnl ##   MANDATORY PLATFORM ENVIRONMENT
dnl ##

AC_MSG_PART(Mandatory Platform Environment)

AC_HEADER_STDC
AC_ISC_POSIX
AC_C_BIGENDIAN

AC_HEADER_STDC
AC_CHECK_HEADERS([stdarg.h stdsoap2.h])
AC_CHECK_FUNCS(strcpy strdup strcmp free malloc open read close fprintf)
AC_CHECK_LIBM
AC_CHECK_DECLS([va_copy])

AM_MAINTAINER_MODE

dnl ##
dnl ##
dnl ##

AC_MSG_PART(Posix Thread Environment)

AC_CHECK_HEADERS(string.h strings.h stdarg.h unistd.h)
dnl ## AC_HAVE_LIBRARY(socket)

AC_MSG_PART(Support libraries)
AC_CHECK_LIB(ev, event_init, , AC_MSG_ERROR(Required libev missing) )
AC_CHECK_LIB(axtls, x509_new)
AC_CHECK_LIB(polarssl, ssl_init)

AC_ARG_WITH(ipt-ACCOUNT,
	[AC_HELP_STRING([--without-ipt-ACCOUNT],
			[build without ipt_ACCOUNT support])],
	[],
	[with_ipt_ACCOUNT=yes])
AS_IF([test "x$with_ipt_ACCOUNT" != "xno"], [
	AC_CHECK_LIB(ipt_ACCOUNT, ipt_ACCOUNT_init)
	AC_CHECK_LIB(xt_ACCOUNT_cl, ipt_ACCOUNT_init)
	if test "x$ac_cv_lib_xt_ACCOUNT_cl_ipt_ACCOUNT_init" != "xyes" -a "x$ac_cv_lib_ipt_ACCOUNT_ipt_ACCOUNT_init" != "xyes"; then
		AC_MSG_ERROR(Required ipt_ACCOUNT missing)
	fi
])

AC_CHECK_LIB(dl, dlopen)
AC_CHECK_LIB(rt, clock_gettime)
AC_CHECK_LIB(crypt, crypt)
AC_CHECK_LIB(pcap, pcap_open_live, , AC_MSG_ERROR(Required libpcap missing) )
AC_CHECK_LIB(cares, ares_init, , AC_MSG_ERROR(Required libcares missing) )
AC_CHECK_LIB([lua], lua_call, , [have_liblua=no], [-ldl -lm])
if test x$have_liblua = xno; then
   AC_CHECK_LIB([lua5.1], lua_call, , AC_MSG_ERROR(Required liblua missing), [-ldl -lm])
fi
AC_CHECK_LIB(talloc, talloc_named_const, , AC_MSG_ERROR(Required libtalloc missing) )

AS_IF([test "x$with_ipt_ACCOUNT" != "xno"], [
	AC_CHECK_HEADERS([ipt_ACCOUNT_cl.h])
	AC_CHECK_HEADERS([libxt_ACCOUNT_cl.h], [], [],
	[
	#include <stdint.h>
	#include <linux/types.h>
	])
	if test "x$ac_cv_header_ipt_ACCOUNT_cl_h" != "xyes" -a "x$ac_cv_header_libxt_ACCOUNT_cl_h" != "xyes"; then
		AC_MSG_ERROR(Required headers for libipt_ACCOUNT missing)
	fi
])

AC_CHECK_HEADERS([libiptc/libiptc.h])
AC_CHECK_HEADERS([ssl.h])

save_LIBS=$LIBS

AC_CHECK_LIB(httpget, http_get, , AC_MSG_ERROR(Required libhttpget missing))
AC_CHECK_HEADER(pthread.h, , AC_MSG_ERROR(You need the pthread headers) )
AC_CHECK_LIB(pthread, pthread_create, , AC_MSG_ERROR(You need the pthread library) )

AC_CHECK_LIB(z, inflate)
AC_CHECK_LIB(expat, XML_Parse, , AC_MSG_ERROR(Required libexpat missing) )
AC_CHECK_LIB(cgi, cgiInit, , AC_MSG_ERROR(Required cgilib >= 0.5 missing) )

## installed by madwifi
AC_CHECK_HEADERS([madwifi/include/compat.h madwifi/wireless_copy.h])
## /usr/include/madwifi must be in search path
AC_CHECK_HEADERS([net80211/ieee80211.h net80211/ieee80211_ioctl.h], , , [
	#include <madwifi/include/compat.h>
	#include <madwifi/wireless_copy.h>
])

AC_MSG_PART(Platform libraries)
AC_CHECK_LIB(iw, iw_sockets_open)
AC_CHECK_LIB(ticfg, wcfg_ioctl_init)
TR069LIBS=$LIBS
LIBS=$save_LIBS
AC_CHECK_LIB(nvram, nvram_get)
NVRAMLIBS=$LIBS
LIBS=$save_LIBS

dnl
dnl
dnl

AC_MSG_PART(Options)

AC_ARG_ENABLE(gsoap-debug,
	[AC_HELP_STRING([--enable-gsoap-debug],
			[Enable gSOAP sent/receive/debug logging to files in /var/log (default=no)])])
if test x$enable_gsoap_debug = xyes; then
	AC_DEFINE(SOAP_DEBUG, , [gSOAP debug logging support])
	AC_DEFINE(SOAP_MEM_DEBUG, , [gSOAP memory debug])
fi

dnl libdmconfig related options

AC_ARG_ENABLE(libdmconfig-debug,
	[AC_HELP_STRING([--enable-libdmconfig-debug],
			[libdmconfig server and clients dump diameter packets to stderr before sending them [default=no]])])
if test x$enable_libdmconfig_debug = xyes; then
	AC_DEFINE(LIBDMCONFIG_DEBUG, , [Dump diameter packets to stderr before sending them])
fi
AM_CONDITIONAL(LIBDMCONFIG_DEBUG, test x$enable_libdmconfig_debug = xyes)

AC_ARG_ENABLE(libdmconfig-luawrapper,
	AC_HELP_STRING([--enable-libdmconfig-luawrapper],
		       [Include abstract Lua interface in libdmconfig [[default=yes]]]), ,
	[enable_libdmconfig_luawrapper=yes])
if test x$enable_libdmconfig_luawrapper = xyes; then
	if test x$LUAC = x; then
		AC_MSG_ERROR([Lua 5.1 compiler not found!])
	fi
	AC_DEFINE(LIBDMCONFIG_LUAWRAPPER, , [Include abstract Lua interface in libdmconfig])
fi
AM_CONDITIONAL(LIBDMCONFIG_LUAWRAPPER, test x$enable_libdmconfig_luawrapper = xyes)

AC_ARG_ENABLE(luacstrip,
	AC_HELP_STRING([--enable-luacstrip], [Tells the Lua compiler to strip debugging information from compiled Lua code [[default=yes]]]),
[case "${enableval}" in
  yes) luacstrip=true ;;
  no)  luacstrip=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-luacstrip) ;;
esac],[luacstrip=true])

LUACFLAGS=
if test x$luacstrip = xtrue; then
	LUACFLAGS+="-s"
fi
AC_SUBST(LUACFLAGS)

AC_ARG_ENABLE(lua-libdir,
	AC_HELP_STRING([--enable-lua-libdir=DIR],
		       [Install Lua libraries/links into this directory [[LIBDIR/lua/5.1]]]),
	[lualibdir=$enable_lua_libdir], [lualibdir=${libdir}/lua/5.1])
AC_SUBST(lualibdir)

AC_ARG_ENABLE(lua-functions,
	AC_HELP_STRING([--enable-lua-functions=DIR],
		       [Install Lua event functions into this directory and look for them there at runtime [[/tmp]]]),
	[luafunctions=$enable_lua_functions], [luafunctions=/tmp])
AC_DEFINE_UNQUOTED(LUA_FUNCTIONS_PATH, "$luafunctions", [Directory containing Lua event functions])
luafunctionsdir=${DESTDIR}$luafunctions
AC_SUBST(luafunctionsdir)

dnl dmconfigincdir=${includedir}/libdmconfig
dnl AC_SUBST(dmconfigincdir)

AC_ARG_ENABLE(fwformat,
	[AC_HELP_STRING([--enable-fwformat],
			[specifiy which firmwareloader should be included (trx,cfe,tpfu)])])
AM_CONDITIONAL(FW_TRX, test "x$enable_fwformat" = xtrx)
AM_CONDITIONAL(FW_CFE, test "x$enable_fwformat" = xcfe)
AM_CONDITIONAL(FW_TPFU, test "x$enable_fwformat" = xtpfu)
AM_CONDITIONAL(FW_RED, test "x$enable_fwformat" = xredboot)

AC_ARG_WITH(udev,
	[AC_HELP_STRING([--with-udev],
			[build with linux 2.6 udev support [default=yes]])], [], [])
if test "$with_udev" != "no"; then
	AC_DEFINE([WITH_UDEV], [], [build with support for linux 2.6 udev])
fi

AC_ARG_WITH(atm,
	[AC_HELP_STRING([--with-atm],
			[build with support for builtin ATM modems])],
	[AC_DEFINE([WITH_ATM], [], build with support for builtin ATM modems[])], [])
AM_CONDITIONAL(ATM, test "${with_atm+set}" = set)

AC_ARG_WITH(brcm43xx,
	[AC_HELP_STRING([--with-brcm43xx],
			[build support for brcm43xx wl driver])],
	[AC_DEFINE([WITH_BRCM43XX], [], [build with support for brcm43xx wl driver])], [])
AM_CONDITIONAL(BRCM43XX, test "${with_brcm43xx+set}" = set)

AC_ARG_WITH(bcm63xx,
	[AC_HELP_STRING([--with-bcm63xx],
			[build support for bcm63xx platform])],
	[AC_DEFINE([WITH_BCM63XX], [], [build with support for bcm63xx platform])], [])
AM_CONDITIONAL(BCM63XX, test "${with_bcm63xx+set}" = set)

AC_ARG_WITH(ar7,
	[AC_HELP_STRING([--with-ar7],
			[build support for TI AR7 platform])],
	[AC_DEFINE([WITH_AR7], [], [build with support for TI AR7 platform])], [])
AM_CONDITIONAL(AR7, test "${with_ar7+set}" = set)

AC_ARG_WITH(bullet,
	{AC_HELP_STRING([--with-bullet],
			[build support for Bullet device])],
	[AC_DEFINE([WITH_BULLET], [], [build support for Bullet device])], [])

AC_ARG_WITH(kernel,
	[AC_HELP_STRING([--with-kernel=<x.x.x>],
			[build support for kerner version])],
	[ac_cv_use_kernel=$withval], [ac_cv_use_kernel=2.4.18])
AC_SET_VERSIONLEVEL([KERNEL_VERSION], [$ac_cv_use_kernel])
AC_DEFINE_UNQUOTED([KERNEL_VERSION], [$KERNEL_VERSION], [build with support for kerner version x.x.x])

AC_ARG_WITH(net-snmp,
	[AC_HELP_STRING([--with-net-snmp],
			[build with support for net-snmp])],
	[AC_DEFINE([WITH_NET_SNMP], [], build with support for net-snmp[])], [])
AM_CONDITIONAL(NET_SNMP, test "${with_net_snmp+set}" = set)

dnl UCD SNMP/Net-SNMP Check
SNMP_LIBS=''

AC_ARG_WITH(net-snmp-agentx,
	[AC_HELP_STRING([--with-net-snmp-agentx=<PATH>],
			[build net-snmp based AgentX support (with PATH as the location of the net-snmp-config shell script that comes with the net-snmp package, if supplied)])],
[
        if test $withval = no
        then
                want_netsnmp=no
		build_agentx=no
        elif test $withval = yes
        then
                want_netsnmp=yes
		build_agentx=yes
        else
                want_netsnmp=yes
		build_agentx=yes
                netsnmpconfig="$withval"
        fi
],[
        #
        # Set "want_netsnmp" to "ifavailable" to make the default "use it
        # if you find it, otherwise don't".
        #
        want_netsnmp=ifavailable
])

#
# Try Net-SNMP.
#
AC_MSG_CHECKING(whether to use Net-SNMP library)
if test "x$want_netsnmp" = "xno" ; then
        AC_MSG_RESULT(no)
else
        if test "x$want_netsnmp" = "xifavailable" ; then
                AC_MSG_RESULT([yes, if available])
        else
                AC_MSG_RESULT(yes)
        fi
        AC_NETSNMP_CHECK
fi
AM_CONDITIONAL(AGENTX, test x$have_net_snmp = xyes)

AC_ARG_WITH(puresnmpd,
	[AC_HELP_STRING([--with-puresnmpd],
			[build with support for puresnmpd])],
	[AC_DEFINE([WITH_PURESNMPD], [], build with support for puresnmpd[])], [])
AM_CONDITIONAL(PURESNMPD, test "${with_puresnmpd+set}" = set)

AC_ARG_WITH(kexec,
	[AC_HELP_STRING([--with-kexec],
			[build with support for kexec])],
	[AC_DEFINE([WITH_KEXEC], [], build with support for kexec[])], [])

AC_ARG_WITH(scgfw,
	[AC_HELP_STRING([--with-scgfw],
			[build with extended SCG firewall ruleset])],
	[AC_DEFINE([WITH_SCG_FW], [], build with extended SCG firewall ruleset[])], [])
AM_CONDITIONAL(SCG_FW, test "${with_scgfw+set}" = set)

AC_ARG_WITH(lngfw,
	[AC_HELP_STRING([--with-lngfw],
			[build with smaller LNG firewall ruleset])],
	[AC_DEFINE([WITH_LNG_FW], [], build with smaller LNG firewall ruleset[])], [])
AM_CONDITIONAL(LNG_FW, test "${with_lngfw+set}" = set)

AC_ARG_WITH(dhcp,
	[AC_HELP_STRING([--with-dhcp=<dhcpd,dnsmasq,internal>],
			[build with support for dhcp via dhcpd, dnsmasq or internal])],
[
	case $withval in
	yes|internal) dhcp_internal=true
		      AC_DEFINE([WITH_DHCP_INTERNAL], [], build with support for internal DHCP)
		      ;;

	dhcpd)	      dhcp_dhcpd=true
		      AC_DEFINE([WITH_DHCP_DHCPD], [], build with support for dhcpd)
		      ;;
	dnsmasq)      dhcp_dnsmasq=true
		      AC_DEFINE([WITH_DHCP_DNSMASQ], [], build with support for dnsmasq)
		      ;;
	*)	      AC_MSG_ERROR([--with-dhcp only dhcpd, dnsmasq or internal allowed])
		      ;;
	esac
],[
	dhcp_internal=true
	AC_DEFINE([WITH_DHCP_INTERNAL], [], build with support for internal DHCP)
])
AM_CONDITIONAL([DHCP_INTERNAL], [test x$dhcp_internal = xtrue])
AM_CONDITIONAL([DHCP_DHCPD],    [test x$dhcp_dhcpd = xtrue])
AM_CONDITIONAL([DHCP_DNSMASQ],  [test x$dhcp_dnsmasq = xtrue])

AC_ARG_WITH(conntrack-tools,
	[AC_HELP_STRING([--with-conntrack-tools],
			[build with support for conntrack-tools])],
	[AC_DEFINE([WITH_CONNTRACK_TOOLS], [], build with support for conntrack-tools)], [])

AC_SUBST(LIBTOOL_DEPS)
AC_SUBST(LIBM)
AC_SUBST(TR069LIBS)
AC_SUBST(NVRAMLIBS)
AC_SUBST(FWFORMAT)

CFLAGS="$CFLAGS -Wall -Wextra -Wstrict-prototypes -Werror=return-type"

#AC_CONFIG_SUBDIRS([gsoap-2.7])
AC_CONFIG_FILES([
	Makefile
	tools/Makefile
	utils/Makefile
	libradius/Makefile
	libdmconfig/Makefile
	libdmconfig/tests/Makefile
	tr069/Makefile
	tr069/snmp/Makefile
	tr069/tests/Makefile
	lua/Makefile
])

AC_OUTPUT

