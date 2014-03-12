# mand - a Device Management Daemon

# Building and Install

## Requirements

- GNU make
- autotools
- autoconf
- libtool
- shtool
- gcc
- libpthreads
- openssl
- expat
- libev (including the event.h compatibility header, libev-libevent-dev package on Debian/Ubuntu)
- libtalloc
- lua 5.1
- lua-event
- xsltproc
- perl
- perl Text/CSV module
- perl DEPS::Transform module

## Optional tools and libraries

- net-snmp

## Build and Install

* rebuild automake and friends

	./autogen.sh

* configure

	./configure --prefix=/usr

  If lua installed it's header in a special place use something like:

	CFLAGS=-I/usr/include/lua5.1 ./configure --prefix=/usr

* build and install

	make 
	make install

# Documentation

libdmconfig API documentation can be build with doxygen:

	make doxygen-doc

For how to use this API, refer to the C and Lua samples in libdmconfig/tests.

