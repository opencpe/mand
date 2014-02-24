#ifndef __DM_STRINGS_H
#define __DM_STRINGS_H

#include <stdint.h>

#include "dm_token.h"

const char* ticks2str(char *, size_t, ticks_t);
int str2ticks(const char *, ticks_t *);

DM_RESULT dm_string2value(const struct dm_element *elem, const char *str, uint8_t set_update, DM_VALUE *value);
dm_selector *dm_name2sel(const char *, dm_selector *);

#endif
