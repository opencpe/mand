#
# SYNOPSIS
#
#   AC_SET_VERSIONLEVEL(VARNAME [,VERSION])
#
# DESCRIPTION
#
#   If the VERSION is ommitted, shellvar $VERSION is used as defined by
#   AM_INIT_AUTOMAKE's second argument.
#
#   The versionlevel is the numeric representation of the given version
#   string, thereby assuming the inputversion is a string with
#   (maximal) three decimal numbers seperated by "."-dots. A "-patch"
#   adds a percent.
#
#   Typical usage:
#
#    AM_INIT_AUTOMAKE(mypkg,4.12.3)
#    AC_SET_VERSIONLEVEL(MYPKG_VERSION)
#    AC_DEFINE_UNQUOTED(MYPKG_VERSION, $MYPKG_VERSION, [package version])
#
#   The version code has three digits per part which I feel is the most
#   natural encoding - it makes it easier to be printf'd anyway.
#
#   Examples:
#
#          3.1           3010000
#          3.11          3110000
#          2.2.18        2020018
#          2.0.112       2000112
#          2.4.2         2040002
#          5.0           5000000
#          0.30.17       30017
#

AC_DEFUN([AC_SET_VERSIONLEVEL],
[dnl
AC_MSG_CHECKING( $1 versionlevel ifelse($2, , $VERSION, $2))
$1=`echo ifelse($2, , $VERSION, $2) | awk -F . '{printf "%d%03d%03d", $[1], $[2], $[3]}'`
AC_MSG_RESULT($[$1])
dnl AC_DEFINE_UNQUOTED( $1, $[$1], ifelse( $3, , $PACKAGE versionlevel, $3))
])
