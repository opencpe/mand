/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_SERIALIZE_H
#define __DM_SERIALIZE_H

#include <stdio.h>

#include "dm.h"
#include "dm_token.h"

#define S_CFG  (1 << 0)
#define S_ACS  (1 << 1)
#define S_SYS  (1 << 2)
#define S_ALL  (S_CFG | S_ACS | S_SYS)

struct dm_enum notify_attr;

void dm_serialize_store(FILE *stream, int flags);
void dm_serialize_element(FILE *stream, const char *element, int flags);

#endif /* __DM_SERIALIZE_H */
