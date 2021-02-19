# mand - a Device Management Daemon

mand is a model driven storage daemon for device management applications. It's main features are:
- storage engine with model driven data verification
- in-memory during runtime for high performance on low-end devices
- persist to storage on request (not for every change to save flash write cycles)
- access API geared toward typical device management task and external API's, including:
  - model driven RPC API
  - get/set/list functionality
  - atomic commit of multiple set operations
  - publish/subcribe on value changes
  - dependency ordered actions, activated on value change/commit

mand is designed to be the binding and storage element connection protocol specific frontends
(e.g. freenetconfd for NETCONF) with configation agents (e.g. mand-cfg) that apply configuration
changes on a given target device. It also routes special purpose RPC's from the frontend to
the agent. mand is management protocol and data model agnostic.

The protocol frontend is responsible for handling the external connection and for translating
request and answers to and from the mand dmconfig API. The frontend are protocol depend and
mostly data model agnostic.

The configuration agents are responsible for acting on values changes and apply them to the
device running config and for reporting status information. They also implement special
purpose API's (like for example firmware upgrade API). Configuration agents are data model
aware and depend on particular entries in those models.

# Building and Install

## Requirements

- GNU make
- autotools
- autoconf
- libtool
- shtool
- gcc
- libpthreads
- expat
- libev
- libtalloc
- lua 5.1 - 5.3
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

**NOTE:** Currently only the [event_client_sample.c](libdmconfig/tests/event_client_sample.c)
example builds and reflects the current state of the API.

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

*IMPORTANT NOTE:* mand is *NOT* a netconf mapper nor a netconf frontend.
It merly uses YANG models to define and represent its internal data
model in a standardized way.
To actually use mand with netconf, a netconf mapper like freenetconfd
is needed. When adding new models to mand, it might be neccessary to also
adjust protocol frontends (like freenetconfd) to support the new models.

# Adding new RPC's

libdmconfig has stubs and skeletons for RPC's. Currently, those need to be
implemented manually. The existing code can easily be used as sample to
write code for new RPC's and can be found in `libdmconfig/*_rpc_{skel,stub}.[ch]`

*NOTE:* There are plans to replace the manual stubs and skeletons with
autogenerate versions. The existing code intentional uses verbose and
repetive patterns that mimick what generate code would look like.
*DO NOT* attempt to optimize or streamline that code.

[1]: http://tools.ietf.org/html/rfc6020
