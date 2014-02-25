/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef __DM_SIGNATURE_H
#define __DM_SIGNATURE_H

int sign_file(const char *source, const char *dest);
int validate_file(const char *source, const char *dest);

#endif
