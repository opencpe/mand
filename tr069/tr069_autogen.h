#ifndef __TR069_AUTOGEN_H
#define __TR069_AUTOGEN_H

#include <stdlib.h>

#include "tr069_token.h"

#define AG_NULL		0
#define AG_HNAME	1
#define AG_SSID		2
#define AG_TNLNM	3
#define AG_CWMPUN	4
#define AG_ERROR	-1

typedef struct {
	tr069_selector entry;
	int type;
} auto_default_val;

typedef struct {
	int members;
	int max_mbrs;
	auto_default_val *storage;
} auto_default_store;

extern auto_default_store def_store;

static inline void free_auto_default_store(void)
{
	free(def_store.storage);
}

int init_auto_default_store(void);
int add_auto_default_entry(struct tr069_value_table *, tr069_id, int);
int generate_auto_defaults(const char *);

#endif
