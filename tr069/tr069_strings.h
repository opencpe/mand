#ifndef __TR069_STRINGS_H
#define __TR069_STRINGS_H

#include <stdint.h>

#include "tr069_token.h"

const char* ticks2str(char *, size_t, ticks_t);
int str2ticks(const char *, ticks_t *);

DM_RESULT tr069_string2value(const struct tr069_element *elem, const char *str, uint8_t set_update, DM_VALUE *value);
tr069_selector *tr069_name2sel(const char *, tr069_selector *);

#endif
