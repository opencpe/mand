/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_DESERIALIZE_H
#define __DM_DESERIALIZE_H

#include <stdio.h>

#include "dm.h"
#include "dm_token.h"

extern struct dm_enum notify_attr;

#define DS_BASECONFIG   (1 << 0)
#define DS_USERCONFIG   (1 << 1)
#define DS_VERSIONCHECK (1 << 2)

int dm_deserialize_store(FILE *, int);
int dm_deserialize_file(const char *, int);
int dm_deserialize_directory(const char *, int);

#endif /* __DM_DESERIALIZE_H */
