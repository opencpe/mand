#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "tr069_token.h"

const struct tr069_element *find_token(const struct tr069_table *kw, const char *cp)
{
	const struct tr069_element *kwe;

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

int tr069_find_token(const char *param, struct tr069_token *token)
{
	char *p;
        char *st;
	const struct tr069_table *kw;
	const struct tr069_element *kwe;
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

