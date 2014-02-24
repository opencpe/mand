/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) Travelping GmbH <info@travelping.com>
 *
 */

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

#include <event.h>

#include <features.h>
#include "tr069.h"

#define SDEBUG
#include "debug.h"

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_serialize.h"
#include "tr069_deserialize.h"
#include "tr069_strings.h"
#include "tr069_notify.h"

#define DEBUG 1

#ifdef WITH_OPENSSL
int CRYPTO_thread_setup(void);
void CRYPTO_thread_cleanup(void);
#endif

void tr069_startup(void)
{
	pthread_t tid;
	struct timeval tv;

#ifdef WITH_OPENSSL
	if (CRYPTO_thread_setup()) {
		fprintf(stderr, "Cannot setup crypto thread mutex\n" );
	}
#endif
}

void tr069_shutdown()
{
#ifdef WITH_OPENSSL
	CRYPTO_thread_cleanup();
#endif
}
