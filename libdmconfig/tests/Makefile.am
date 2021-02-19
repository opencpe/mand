# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

## libdmconfig test/sample programs
## not part of a test suite

AM_CFLAGS = -g -std=gnu99 \
	-I$(top_srcdir)

check_PROGRAMS = event_client_sample
#check_PROGRAMS = client_sample polling_sample dm_sample \
#		 event_client_sample event_notify_sample

LDADD = ../libdmconfig.la ../libdm_dmclient.la
