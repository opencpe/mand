#ifndef __TR069_DESERIALIZE_H
#define __TR069_DESERIALIZE_H

#include <stdio.h>

#include "tr069.h"
#include "tr069_token.h"

extern struct tr069_enum notify_attr;

#define DS_BASECONFIG   (1 << 0)
#define DS_USERCONFIG   (1 << 1)
#define DS_VERSIONCHECK (1 << 2)

int tr069_deserialize_store(FILE *, int);
int tr069_deserialize_file(const char *, int);
int tr069_deserialize_directory(const char *, int);

#endif /* __TR069_DESERIALIZE_H */
