#ifndef __SOAPDEFS_H
#define __SOAPDEFS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define WITH_COOKIES
#define SOCKET_CLOSE_ON_EXEC

#if defined(HAVE_LIBPOLARSSL)
#define WITH_POLARSSL
#elif defined(HAVE_LIBAXTLS)
#include "tools/axtls-config.h"

#define WITH_AXTLS
#elif defined(HAVE_LIBSSL)
#define WITH_OPENSSL
#endif

#endif /* __SOAPDEFS_H */
