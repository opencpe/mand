#
# AC_NETSNMP_CHECK
#
AC_DEFUN([AC_NETSNMP_CHECK],
[
	dnl get the net-snmp-config binary
	if test "x$netsnmpconfig" = "x" ; then
		#
		# The user didn't specify where net-snmp-config is
		# located; search for it.
		#
		AC_PATH_PROG(NETSNMPCONFIG, net-snmp-config)
	else
		NETSNMPCONFIG=$netsnmpconfig
		if test ! -x $NETSNMPCONFIG -o ! -f $NETSNMPCONFIG ; then
			NETSNMPCONFIG=$netsnmpconfig/bin/net-snmp-config
			if test ! -x $NETSNMPCONFIG -o ! -f $NETSNMPCONFIG ; then
				AC_MSG_ERROR(Invalid net-snmp-config: $netsnmpconfig)
			fi
		fi
	fi

	#
	# XXX - check whether $NETSNMPCONFIG is executable?
	# if test "x$NETSNMPCONFIG" != "xno" -a "x$NETSNMPCONFIG" != "x" -a -x "$NETSNMPCONFIG" ; then
	# We already did that if it was set; presumably AC_PATH_PROG
	# will fail if it doesn't find an executable version.
	#
	if test "x$NETSNMPCONFIG" != "x" ; then
		dnl other choices for flags to use here: could also use
		dnl --prefix or --exec-prefix if you don't want the full list.

		AC_CHECK_HEADERS(net-snmp/net-snmp-config.h net-snmp/library/default_store.h)
		if test "x$ac_cv_header_net_snmp_net_snmp_config_h" = "xyes" -a "x$ac_cv_header_net_snmp_library_default_store_h" = "xyes" ; then
			AC_SUBST(SNMP_LIBS)
			SNMP_LIBS="$($NETSNMPCONFIG --base-agent-libs) $($NETSNMPCONFIG --external-agent-libs)"
			AC_DEFINE(HAVE_NET_SNMP, 1, [Define to enable support for Net-SNMP])
			have_net_snmp="yes"
		else
			if test "x$want_netsnmp" = "xyes" ; then
				AC_MSG_ERROR(Net-SNMP not found)
			fi
		fi
	fi	
])
