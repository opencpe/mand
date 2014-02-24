ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -DWITH_SOAPDEFS_H

SUBDIRS = utils libdmconfig libdmconfig/tests tr069 lua

LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

#   Makefile entry for upgrading GNU tools
upgrade-tools:
	libtoolize -f -c
	shtoolize -q all

