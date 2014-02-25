/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "dm_token.h"

const struct dm_element *find_token(const struct dm_table *kw, const char *cp)
{
	const struct dm_element *kwe;

        if (!kw)
                return NULL;

	kwe = kw->table;
        while (kwe->key) {
                if (strcmp(cp, kwe->key) == 0)
                        return kwe;
                kwe++;
        }
        return NULL;
}

int dm_find_token(const char *param, struct dm_token *token)
{
	char *p;
        char *st;
	const struct dm_table *kw;
	const struct dm_element *kwe;
	int l;
	int ret = 0;

	if (!token)
		return 0;

	memset(token, 0, sizeof(token));
	p = strdup(param);
	l = 0;

	st = strtok(p, ".");
	kw = &dm_root;
	while (kw && st) {
		kwe = find_token(kw, st);
		if (!kwe)
			break;
 		if (kwe->type == T_TOKEN) {
			st = strtok(NULL, ".");
			kw = kwe->u.t.table;
			continue;
		} else if (kwe->type == T_OBJECT) {
			st = strtok(NULL, ".");
			if (!st)
				break;
			token->cntr[l++] = atoi(st);
			st = strtok(NULL, ".");
			kw = kwe->u.t.table;
		} else if (kwe->type == T_FKT) {
			token->element = kwe;
			ret = 1;
			break;
		} else
			printf("parser error\n");
	}
	free(p);
	return ret;
}

