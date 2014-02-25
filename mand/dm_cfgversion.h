/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __HAVE_DM_CFGVERSION_H
#define __HAVE_DM_CFGVERSION_H

#define CFG_VERSION  1

int dm_get_cfg_version(void);
void dm_set_cfg_version(int v);

#endif
