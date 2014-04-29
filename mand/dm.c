/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#include <sys/reboot.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stdarg.h>
#include <syslog.h>

#include <features.h>
#include "dm.h"

#define SDEBUG
#include "debug.h"

#include "dm_token.h"
#include "dm_store.h"
#include "dm_serialize.h"
#include "dm_deserialize.h"
#include "dm_strings.h"
#include "dm_notify.h"

#define DEBUG 1

#ifdef WITH_OPENSSL
int CRYPTO_thread_setup(void);
void CRYPTO_thread_cleanup(void);
#endif

void dm_startup(void)
{
#ifdef WITH_OPENSSL
	if (CRYPTO_thread_setup()) {
		fprintf(stderr, "Cannot setup crypto thread mutex\n" );
	}
#endif
}

void dm_shutdown()
{
#ifdef WITH_OPENSSL
	CRYPTO_thread_cleanup();
#endif
}
