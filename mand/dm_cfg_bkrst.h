/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_CFG_BKRST_H
#define __DM_CFG_BKRST_H

#include "dm_token.h"

DM_RESULT save_conf(char *url);
DM_RESULT restore_conf(char *url);

#endif
