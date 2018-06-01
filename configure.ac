dnl # This Source Code Form is subject to the terms of the Mozilla Public
dnl # License, v. 2.0. If a copy of the MPL was not distributed with this
dnl # file, You can obtain one at http://mozilla.org/MPL/2.0/.

dnl ## standard Autoconf prolog

AC_PREREQ(2.59)

AC_INIT([mand], [1.0], [support@travelping.com])
AC_CONFIG_SRCDIR(mand/mand.c)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([])

AC_SRCDIR_PREFIX(srcdir_prefix)
AC_HEADLINE(dnl
TPLINO Device Config Agent)
AC_CONFIG_PARAM(config.param)
AM_CONFIG_HEADER(config.h)
AC_PREFIX_DEFAULT(/usr)
AC_PLATFORM(PLATFORM)


dnl ##
dnl ##  BUILD TOOLS
dnl ##

AC_MSG_PART(Build Tools)

AM_PATH_PYTHON
AX_PYTHON_MODULE([pyang], [true])
AC_CHECK_PROG(PYANG, pyang, pyang)

AC_CANONICAL_HOST
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CPP
AM_PROG_CC_C_O
AC_CHECK_PROG(LUAC, luac, luac)
AC_CHECK_PROG(LUAC, luac5.1, luac5.1)
AC_CHECK_HEADER(lua.h, , AC_MSG_ERROR(You need the lua headers) )
AC_PROG_INSTALL
AC_SET_MAKE
AC_CHECK_DEBUGGING
AC_CHECK_PROG(XSLTPROC, xsltproc, xsltproc)
if test x$XSLTPROC = x; then
   AC_MSG_ERROR([Couldn't find xsltproc (XSLT processor)])
fi

AC_MSG_PART(Configure libtool)
AM_PROG_LIBTOOL

AC_MSG_PART(doxygen support)
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)

DX_INIT_DOXYGEN([$PACKAGE_NAME],[doxygen.cfg])

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

AC_CHECK_LIB(dl, dlopen)
AC_CHECK_LIB(rt, clock_gettime)
AC_CHECK_LIB(crypt, crypt)
AC_CHECK_LIB([lua], lua_callk, , [have_liblua=no], [-ldl -lm])
if test x$have_liblua = xno; then
   AC_CHECK_LIB([lua5.1], lua_call, , AC_MSG_ERROR(Required liblua missing), [-ldl -lm])
fi
AC_CHECK_LIB(talloc, talloc_named_const, , AC_MSG_ERROR(Required libtalloc missing) )
AC_CHECK_HEADERS([talloc.h talloc/talloc.h])

save_LIBS=$LIBS

AC_CHECK_HEADER(pthread.h, , AC_MSG_ERROR(You need the pthread headers) )
AC_CHECK_LIB(pthread, pthread_create, , AC_MSG_ERROR(You need the pthread library) )

AC_CHECK_LIB(expat, XML_Parse, , AC_MSG_ERROR(Required libexpat missing) )

dnl
dnl
dnl

AC_MSG_PART(Options)

dnl libdmconfig related options

AC_ARG_ENABLE(libdmconfig-debug,
	[AC_HELP_STRING([--enable-libdmconfig-debug],
			[libdmconfig server and clients dump dmconfig packets to stderr before sending them [default=no]])])
if test x$enable_libdmconfig_debug = xyes; then
	AC_DEFINE(LIBDMCONFIG_DEBUG, , [Dump dmconfig packets to stderr before sending them])
fi
AM_CONDITIONAL(LIBDMCONFIG_DEBUG, test x$enable_libdmconfig_debug = xyes)

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
AM_CONDITIONAL(AGENTX, test x$want_netsnmp = xyes)

AC_SUBST(LIBTOOL_DEPS)
AC_SUBST(LIBM)
AC_SUBST(DMLIBS)

CFLAGS="$CFLAGS -Wall -Wextra -Wstrict-prototypes -Werror=return-type"

AC_CONFIG_FILES([
	Makefile
	utils/Makefile
	libdmconfig/Makefile
	libdmconfig/tests/Makefile
	mand/Makefile
	mand/snmp/Makefile
	mand/tests/Makefile
	lua/Makefile
])

AC_OUTPUT

