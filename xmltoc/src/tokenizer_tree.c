/*
	common functions for internal tree processing and conversion tasks
*/

#define _GNU_SOURCE

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "tr_common.h"
#include "tokenizer_tree.h"

extern MAPPINGS mappings;

int id = 1;
NODE *head = NULL;
NODE *node = NULL;

const char cntrVar[] = "ijklmn";

static const char *t_types[] = {
	"T_TOKEN",
	"T_OBJECT",
	"T_FKT",
	"T_UINT",
	"T_INT",
	"T_BOOL",
	"T_STR",
	"T_BASE64",
	"T_DATE",
	"T_COUNTER",
	"T_ENUM",
	"T_SELECTOR"
};

		/* create C code from tree structure - largely borrowed from "tokenizer.c" */

NODE *
insertNode(NODE **next, char *s, char *alias, int tid, int get, int set) {
	NODE *n;

	if(!(n = malloc(sizeof(NODE))))
		MISCERR(ERR_MEM)
	memset(n, 0, sizeof(NODE));
	if(!(n->name = strdup(s)))
		MISCERR(ERR_MEM)
	n->get = get;
	n->set = set;
	if (alias)
		n->alias = strdup(alias);
	else
		n->alias = strdup(s);
		/*
		snprintf(buf, 32, "%d", id);
		n->alias = strdup(buf);
		*/
	if(!n->alias)
		MISCERR(ERR_MEM)
	n->items = NULL;
	n->id = id++;
	n->tid = tid;
	n->next = *next;
	*next = n;
	return n;

misc_err:

	if(n) {
		if(n->name)
			free(n->name);
		if(n->alias)
			free(n->alias);
		free(n);
	}
	return NULL;
}

NODE *
addNode(NODE *node, char *s, char *alias, int get, int set) {
	NODE **p, *n;
	int tid;

	n = node->items;
	p = &node->items;

	for(tid = 0; n; tid++) {
		if (!strcmp(n->name, s))
			return n;
		p = &n->next;
		n = n->next;
	}
	return insertNode(p, s, alias, tid, get, set);
}

NODE *
addObject(NODE *n, char *name, char *alias) {
	char *s; char sbb[512]; char *sb = sbb;

	s = strtok_r(name, ".", &sb);
	while (s && *s) {
		if(!(n = addNode(n, s, alias, 0, 0)))
			return NULL;
		s = strtok_r(NULL, ".", &sb);
	}

	return n;
}

void
print_flag(FILE *f, const char *flag, int *first) {
	if (!(*first))
		fprintf(f, " | ");
	else
		*first = 0;

	fprintf(f, flag);
}

int
getNodeId(NODE *i, const char *ref) {
	NODE *n;

	for (n = i; n; n = n->next)
		if (strcmp(n->name, ref) == 0)
			return n->tid;

	printf("WARNING: couldn't find reference: %s\n", ref);
	return 0;
}

void
genKeywordTab(FILE *f, FILE *h, NODE *i, const char *base, int cntCntr) {
	int cnt = 0;
	int size;
	NODE *n;

	for (n = i, size = 0; n; n = n->next)
		if (n->name[0] != '{')
			size = n->tid > size ? size = n->tid : size;

	n = i;

	while (i) {
		if (i->name[0] != '{') {
			NODE *p = i->items;

			if (!cnt) {
				fprintf(f, "const struct dm_table keyword_%d_tab =\n{\n", i->id);
				fprintf(f, "\tTABLE_NAME(\"%s\")\n", base);
				fprintf(f, "\t.size\t= %d,\n", size);
				fprintf(f, "\t.table\t=\n\t{\n");
			}

			while (cnt < i->tid - 1) {
				fprintf(f, "\t\t{\n\t\t\t.key\t= NULL\n\t\t},\n");
				cnt++;
			}

			fprintf(f, "\t\t{\n\t\t\t.key\t= \"%s\",\n", i->name);

			fprintf(h, "#define cwmp_%s_%s\t\t%d\n", base, i->name, i->tid);

			if ((i->flags != 0 && i->flags != F_TREE_LINK) || i->get || i->set) {
				int first = 1;
				fprintf(f, "\t\t\t.flags\t= ");
				if (i->flags & F_READ)  print_flag(f, "F_READ", &first);
				if (i->flags & F_WRITE) print_flag(f, "F_WRITE", &first);
				if (i->flags & F_SYSTEM) print_flag(f, "F_SYSTEM", &first);
				if (i->type != T_COUNTER) {
					if (i->get) print_flag(f, "F_GET", &first);
					if (i->set) print_flag(f, "F_SET", &first);
				}
				fprintf(f, ",\n");
			}

			if (p) {
				if (p->name[0] == '{') {
					fprintf(f, "\t\t\t.type\t= T_OBJECT,\n");
					p = p->items;
				} else
					fprintf(f, "\t\t\t.type\t= T_TOKEN,\n");
				fprintf(f, "\t\t\t.u.t.table = &keyword_%d_tab\n", p->id);
			} else {
				fprintf(f, "\t\t\t.type\t= %s,\n", t_types[i->type - 1]);
				if (i->type == T_STR) {
					if (i->max != 0 && i->max != INT_MAX)
						fprintf(f, "\t\t\t.u.l.max\t= %d,\n", i->max);
				} else if (i->type == T_INT || i->type == T_UINT) {
					if (i->min != 0)
						fprintf(f, "\t\t\t.u.l.min\t= %d,\n", i->min);
					if (i->max == INT_MAX)
						fprintf(f, "\t\t\t.u.l.max\t= INT_MAX,\n");
					else
						fprintf(f, "\t\t\t.u.l.max\t= %d,\n", i->max);
				} else if (i->type == T_COUNTER) {
					fprintf(f, "\t\t\t.u.counter_ref\t= %d,\n", getNodeId(n, i->count_ref));
				} else if (i->type == T_ENUM) {
					char *s, *e;
					int n = 0;

					fprintf(f, "\t\t\t.u.e\t= { .data = \"");
					e = i->cenum;
					while (e) {
						s = strchr(e, ',');
						if (s)
							*s++ = '\0';
						fprintf(f, "%s", e);
						if (s)
							fprintf(f, "\\000");
						e = s;
						n++;
					}
					fprintf(f, "\", .cnt = %d },\n", n);
				}
				if (i->type != T_COUNTER) {
					if (i->get) {
						fprintf(f, "\t\t\t.fkts.get\t= get%s_%s,\n", base, i->name);
						fprintf(h, "DM_VALUE get%s_%s(const struct dm_element *, DM_VALUE);\n", base, i->name);
					}
					if (i->set) {
						fprintf(f, "\t\t\t.fkts.set\t= set%s_%s\n", base, i->name);
						fprintf(h, "int set%s_%s(const struct dm_element *, DM_VALUE *, DM_VALUE);\n", base, i->name);
					}
				}
			}
			fprintf(f, "\t\t},\n");
			cnt++;
		}

		i = i->next;
	}
	if (cnt) {
		/* fprintf(f, "\t\t{\n\t\t\t.key\t= NULL\n\t\t}\n"); */
		fprintf(f, "\t}\n};\n\n");
	}
}

		/* this one's new: */

unsigned int
genBase(FILE *h, NODE *n, char *base, int cntCntr) {
	NODE *p;
	char buf[1024];
	int cnt;

	if (!n)
		return;

	p = n->items;
	while (p) {
		cnt = cntCntr;
		if (p->name[0] != '{')
			snprintf(buf, sizeof(buf), "%s_%s", base, p->alias);
		else {
			snprintf(buf, sizeof(buf), "%s_%c", base, cntrVar[cntCntr]);
			cnt++;
		}

		if(genBase(h, p, buf, cnt))
			goto misc_err;
		p = p->next;
	}

	if (n->items && n->name[0] != '{') {
		char *nb;
		if(!(nb = strndup(base, strrchr(base, '_') - base)))
			MISCERR(ERR_MEM)
		fprintf(h, "#define cwmp_%s_%s\t\t%d\n", nb, n->name, n->tid);
		free(nb);
	}

	return 0;

misc_err:

	return 1;
}

void
genTablef(FILE *f, FILE *h, NODE *n, const char *base, int cntCntr) {
	NODE *p;
	char buf[1024];
	int cnt;

	if (!n || n->flags == F_TREE_LINK)
		return;

	p = n->items;

	while (p) {
		cnt = cntCntr;
		if (p->name[0] != '{')
			snprintf(buf, sizeof(buf), "%s_%s", base, p->alias);
		else {
			snprintf(buf, sizeof(buf), "%s_%c", base, cntrVar[cntCntr]);
			cnt++;
		}

		genTablef(f, h, p, buf, cnt);
		p = p->next;
	}

	if (n->items)
		genKeywordTab(f, h, n->items, base, cntCntr);
}

unsigned int
BuildAndWriteLinks(FILE *h) {
	char	*name = NULL;
	char	*alias = NULL;
	int	i;

	for(i = 0; i < mappings.links_size; i++) {
		NODE	*cur;
		char	*pp;
		char	*ap1, *ap2;
		char	buf[1024] = {0};

			/* create objects which are new in the link's target
			   also create a base name */

		for(pp = mappings.links[i]->to, ap1 = ap2 = mappings.links[i]->abbr + 1; (int)ap2 != 1; ap1 = ++ap2) {
			if(!(name = strndup(mappings.links[i]->to, (pp = strchr(pp, '.') + 1) - mappings.links[i]->to)) ||
				!(alias = (ap2 = strchr(ap2, '_')) ? strndup(ap1, ap2 - ap1) : strdup(ap1)))
				MISCERR(ERR_MEM)
			if(!(node = addObject(head, name, alias)))
				goto misc_err;
			FREE(free, name)
			FREE(free, alias)
			node->flags = 0;
			strcat(buf, "_");
			if(ap2)
				strncat(buf, ap1, ap2 - ap1);
			else
				strcat(buf, ap1);
		}
		node->flags = F_TREE_LINK;

			/* look for link's origin and assign origin to target */

		for(ap1 = mappings.links[i]->from, ap2 = strchr(ap1, '.'), cur = head->items; ap2 && cur; cur->next)
			if((ap2 && ap2 - ap1 == strlen(cur->name) &&
				!strncmp(ap1, cur->name, ap2 - ap1)) || (!ap2 && !strcmp(ap1, cur->name))) {
				cur = cur->items;
				ap2 = strchr(ap1 = ap2 + 1, '.');
			} else
				cur = cur->next;
		node->items = cur;

		if(!cur)
			MISCERR("Link origin \"%s\" not found", mappings.links[i]->from)

		if(genBase(h, node, buf, 0))
			goto misc_err;
	}

	return 0;

misc_err:

	if(name)
		free(name);
	if(alias)
		free(alias);
	return 1;
}
