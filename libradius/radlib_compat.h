/*
Copyright (c) 2003, Michael Bretterklieber <michael@bretterklieber.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions 
are met:

1. Redistributions of source code must retain the above copyright 
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright 
   notice, this list of conditions and the following disclaimer in the 
   documentation and/or other materials provided with the distribution.
3. The names of the authors may not be used to endorse or promote products 
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

This code cannot simply be copied and put under the GNU Public License or 
any other GPL-like (LGPL, GPL2) License.

    $Id: radlib_compat.h,v 1.6 2003/04/24 18:04:44 mbretter Exp $
*/

#ifndef _RADLIB_COMPAT_H_
#define _RADLIB_COMPAT_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

void srandomdev(void);

#define MPPE_KEY_LEN    16

#ifndef __printflike
#define	__printflike(fmtarg, firstvararg)
#endif

#ifndef timeradd
#define timeradd(tvp, uvp, vvp)		\
	do {		\
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;		\
		if ((vvp)->tv_usec >= 1000000) {		\
			(vvp)->tv_sec++;		\
			(vvp)->tv_usec -= 1000000;		\
		}		\
	} while (0)
#endif

#ifndef timersub
#define timersub(tvp, uvp, vvp)		\
	do {		\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;		\
		if ((vvp)->tv_usec < 0) {		\
			(vvp)->tv_sec--;		\
			(vvp)->tv_usec += 1000000;		\
		}		\
	} while (0)
#endif

#endif
