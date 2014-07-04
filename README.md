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
- python
- pyang

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

# Adding new YANG modules

YANG is specified in [RFC 6020][1]. mand already contains several IETF YANG modules
in yang/specs/, e.g.:

    $ ls -1 yang/specs/*yang
    yang/specs/iana-if-type.yang
    yang/specs/iana-timezones@2012-07-09.yang
    yang/specs/ietf-inet-types@2013-07-15.yang
    yang/specs/ietf-interfaces@2013-07-04.yang
    yang/specs/ietf-ip@2013-10-18.yang
    yang/specs/ietf-netconf-acm@2012-02-22.yang
    yang/specs/ietf-system@2013-11-07.yang
    yang/specs/ietf-yang-types@2013-07-15.yang

To add a new module, simply place the new .yang file in yang/specs and re-run make.
The pyang tool is invoked as:

    pyang --plugindir ../yang/pyang_plugin/ -p ../yang/specs -f OpenCPE ../yang/specs/*.yang

and will generate the necessary instrumentation for mand to support the new module.

After starting mand, the top level hierarchy of all YANG modules can be dumped with:

    mand/dmctrl dump

Sample output with empty values:

    <?xml version="1.0" encoding="UTF-8"?>
    <OpenCPE version="1">
        <system>
            <contact />
            <hostname />
            <location />
            <clock>
                <timezone-location>Europe/Andorra</timezone-location>
                <timezone-utc-offset>120</timezone-utc-offset>
            </clock>
            <ntp>
                <enabled>false</enabled>
            </ntp>
            <dns-resolver>
                <options>
                    <timeout>0</timeout>
                    <attempts>0</attempts>
                </options>
            </dns-resolver>
           ...
        </system>
    </OpenCPE>

Newly added YANG modules would show up as well.

Single values can be set:

    $ mand/dmctrl set system.contact="Test Contact"

and read:

    $ mand/dmctrl get system.contact
    Test Contact

Subtree's can be also be dumped:

    $ mand/dmctrl dump system
    <?xml version="1.0" encoding="UTF-8"?>
    <data>
        <system>
            <contact>Test Contact</contact>
            <hostname />
            <location />
            ...
        </system>
    </data>

[1]: http://tools.ietf.org/html/rfc6020
