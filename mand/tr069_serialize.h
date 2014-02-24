#ifndef __TR069_SERIALIZE_H
#define __TR069_SERIALIZE_H

#include <stdio.h>

#include "tr069.h"
#include "tr069_token.h"

#define S_CFG  (1 << 0)
#define S_ACS  (1 << 1)
#define S_SYS  (1 << 2)
#define S_ALL  (S_CFG | S_ACS | S_SYS)

struct tr069_enum notify_attr;

void tr069_serialize_store(FILE *stream, int flags);
void tr069_serialize_element(FILE *stream, const char *element, int flags);

#endif /* __TR069_SERIALIZE_H */
