ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -DWITH_SOAPDEFS_H

EXTRA_DIST = doxygen.cfg

SUBDIRS = utils libdmconfig libdmconfig/tests mand lua

LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

#   Makefile entry for upgrading GNU tools
upgrade-tools:
	libtoolize -f -c
	shtoolize -q all

if DX_COND_doc
mostlyclean-local: doxygen-clean
endif

include m4/amdoxygen.m4
