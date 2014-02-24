#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

const char cntrVar[] = "ijklmn";

enum {
	T_NONE = 0,
	T_TOKEN,
	T_OBJECT,
	T_FKT,
	T_UINT,
	T_INT,
	T_BOOL,
	T_STR,
	T_BINARY,
	T_BASE64,
	T_DATE,
	T_COUNTER,
	T_ENUM,
	T_SELECTOR,
	T_IPADDR4,
	T_INSTANCE,
	T_UINT64,
	T_INT64,
	T_POINTER,
};

#define type_map_init(x)   [x] = #x

const char *t_types[] = {
	type_map_init(T_TOKEN),
	type_map_init(T_OBJECT),
	type_map_init(T_FKT),
	type_map_init(T_UINT),
	type_map_init(T_INT),
	type_map_init(T_BOOL),
	type_map_init(T_STR),
	type_map_init(T_BINARY),
	type_map_init(T_BASE64),
	type_map_init(T_DATE),
	type_map_init(T_COUNTER),
	type_map_init(T_ENUM),
	type_map_init(T_SELECTOR),
	type_map_init(T_IPADDR4),
	type_map_init(T_INSTANCE),
	type_map_init(T_UINT64),
	type_map_init(T_INT64),
	type_map_init(T_POINTER),
};

struct string_map {
	char *string;
	int   id;
};

#include "actions.h"

#define F_READ		(1 << 0)
#define F_WRITE		(1 << 1)
#define F_SYSTEM	(1 << 2)
#define F_INDEX		(1 << 3)
#define F_NTFY		(1 << 4)
#define F_NO_NTFY	(1 << 5)
#define F_INTERNAL	(1 << 6)
#define F_MAP_ID	(1 << 7)
#define F_VERSION	(1 << 8)

#define CSV_KEY		0
#define CSV_ALIAS	1
#define CSV_COUNT_REF	2
#define CSV_GET_FLAG	2
#define CSV_SET_FLAG	3
#define CSV_DATA_TYPE	4
#define CSV_WRITE_FLAG	5
#define CSV_READ_FLAG	6
#define CSV_SYSTEM_FLAG	7
#define CSV_ACTION	8

#define SFLAG_SYSTEM	0
#define SFLAG_INDEX	1
#define SFLAG_NOTIFY	2
#define SFLAG_MAP_ID	3

int mapcasecmp(const void *p1, const void *p2)
{
	struct string_map *a = (struct string_map *)p1;
	struct string_map *b = (struct string_map *)p2;

	return strcasecmp(a->string, b->string);
}

int mapcmp(const void *p1, const void *p2)
{
	struct string_map *a = (struct string_map *)p1;
	struct string_map *b = (struct string_map *)p2;

	return strcmp(a->string, b->string);
}

int map_string(const char *string,
	       struct string_map *map, size_t nmemb,
	       int(*compar)(const void *, const void *))
{
	struct string_map key = { .string = string };
	struct string_map *res;

	res = bsearch (&key, map, nmemb, sizeof(struct string_map), compar);
	if (res)
		return res->id;

	return -1;
}

void chomp(char *s)
{
	char *p;

	if (!*s)
		return;
	p = s + strlen(s) - 1;
	while (p >= s && isspace(*p))
		p--;
	*(++p) = '\0';
}

inline char strlast(char *s)
{
	if (!*s)
		return '\0';

	return *(s + strlen(s) - 1);
}

struct node {
	struct node *next;
	struct node *items;
	struct node **append;
	int id;
	int tid;
	int cnt;
	char *name;
	char *alias;
	int get, set;
	int flags;
	int code_gen;
	char *count_ref;

	char *cenum;
	int type;
	int min;
	int max;

	int action;
};

int id = 1;
struct node *head = NULL;

struct node *appendNode(struct node *node, char *s, char *alias, int get, int set)
{
	struct node *n;

	n = malloc(sizeof(struct node));
	memset(n, 0, sizeof(struct node));
	n->name = strdup(s);
	n->get = get;
	n->set = set;
	if (alias)
		n->alias = strdup(alias);
	else {
		n->alias = strdup(s);
		/*
		snprintf(buf, 32, "%d", id);
		n->alias = strdup(buf);
		*/
	}
	n->items = NULL;
	n->append = &n->items;

	n->id = id++;
	n->tid = node->cnt + 1;

	*node->append = n;
	node->append = &n->next;
	node->cnt++;

	return n;
}

struct node *findNode(struct node *n, char *name)
{
	char *s; char sbb[512]; char *sb = sbb;

	strncpy(sbb, name, 512);
	s = strtok_r(sbb, ".", &sb);

	while (s && *s && n->items) {
		struct node *p = n->items;

		while (p) {
			if (strcmp(p->name, s) == 0)
				break;
			p = p->next;
		}
		if (!p)
			return n;

		n = p;
		s = strtok_r(NULL, ".", &sb);
	}

	return n;
}

struct node *addNode(struct node *node, char *s, char *alias, int get, int set)
{
	struct node **p, *n, *r;

	printf("add '%s' to '%s'\n", s, node->name);
	r = appendNode(node, s, alias, get, set);
	if (r && s && s[0] == '{')
		r->type = T_INSTANCE;
	return r;
}

struct node *addObject(struct node *n, char *name, char *alias, int get, int set)
{
	char *s; char sbb[512]; char *sb = sbb;

	s = strtok_r(name, ".", &sb);
	while (s && *s) {
		n = addNode(n, s, alias, 0, 0);
		s = strtok_r(NULL, ".", &sb);
	}
	if (n) {
		n->get = get;
		n->set = set;
	}
	return n;
}

int getNodeId(struct node *i, const char *ref)
{
	struct node *n;
	
	for (n = i; n; n = n->next) {
		if (strcmp(n->name, ref) == 0)
			return n->tid;
	}

	printf("WARNING: couldn't find reference: %s\n", ref);
	return 0;
}

#define IDENT  "   "

void print_flag(FILE *f, const char *flag, int *first)
{
	if (!(*first))
		fprintf(f, " | ");
	else
		*first = 0;

	fprintf(f, flag);
}

void genKeywordTab(FILE *f, FILE *h, FILE *stubs, struct node *i, const char *base, int cntCntr, struct node *base_node)
{
	int cnt = 0;
	struct node *n;
	
	if (base_node->type == T_INSTANCE) {
		int idx = 1; 
		fprintf(f, "const struct index_definition index_%d_tab =\n{\n", i->id);
		fprintf(f, "\t/* type: %s, %s */\n", base, t_types[base_node->type]);
		fprintf(f, "\t.idx\t= {\n");
		fprintf(f, "\t\t{ .type = T_INSTANCE },\n");
		for (n = i; n; n = n->next)
			if (n->flags & F_INDEX) {
				idx++;
				fprintf(f, "\t\t{ .type = %s, .element = cwmp_%s_%s },\n", t_types[n->type], base, n->name);
			}
		fprintf(f, "\t},\n");
		fprintf(f, "\t.size\t= %d\n", idx);
		fprintf(f, "};\n\n");
	}

	n = i;

	while (i) {
		if (i->name[0] != '{') {
			struct node *p = i->items;

			if (!cnt) {
				fprintf(f, "const struct dm_table keyword_%d_tab =\n{\n", i->id);
				fprintf(f, "\tTABLE_NAME(\"%s\")\n", base);
				if (base_node->type == T_INSTANCE)
					fprintf(f, "\t.index\t= &index_%d_tab,\n", i->id);
				fprintf(f, "\t.size\t= %d,\n", base_node->cnt);
				fprintf(f, "\t.table\t=\n\t{\n");
			}

			while (cnt < i->tid - 1) {
				fprintf(f, "\t\t{\n\t\t\t.key\t= NULL\n\t\t},\n");
				cnt++;
			}

			fprintf(f, "\t\t{\n\t\t\t/* %d */ \n\t\t\t.key\t= \"%s\",\n", i->tid, i->name);

			fprintf(h, "#define cwmp_%s_%s\t\t%d\n", base, i->name, i->tid);

			if (i->flags != 0 || i->get || i->set ||
			    ((p && p->name[0] == '{') && (p->get || p->set || p->flags & F_MAP_ID))) {
				int first = 1;
				fprintf(f, "\t\t\t.flags\t= ");
				if (i->flags & F_READ)  print_flag(f, "F_READ", &first);
				if (i->flags & F_WRITE) print_flag(f, "F_WRITE", &first);
				if (i->flags & F_SYSTEM) print_flag(f, "F_SYSTEM", &first);
				if (i->flags & F_VERSION) print_flag(f, "F_VERSION", &first);
				if (i->flags & F_INDEX) print_flag(f, "F_INDEX", &first);
				if (i->flags & F_INTERNAL) print_flag(f, "F_INTERNAL", &first);
				if (i->flags & F_NTFY) print_flag(f, "F_ACS_NTFY", &first);
				if (i->flags & F_NO_NTFY) print_flag(f, "F_ACS_NO_NTFY", &first);
				if (p && (p->flags & F_MAP_ID)) print_flag(f, "F_MAP_ID", &first);
				if (i->type != T_COUNTER) {
					if (i->get) print_flag(f, "F_GET", &first);
					if (i->set) print_flag(f, "F_SET", &first);
				}
				if (p && p->name[0] == '{') {
					if (p->get) print_flag(f, "F_ADD", &first);
					if (p->set) print_flag(f, "F_DEL", &first);
				}
				fprintf(f, ",\n");
			}

			fprintf(f, "\t\t\t.action\t= %s,\n", t_actions[i->action]);
			if (p) {
				long max = p->max;

				if (p->name[0] == '{') {
					fprintf(f, "\t\t\t.type\t= T_OBJECT,\n");

					if (p->get || p->set) {
						fprintf(f, "\t\t\t.fkts.instance\t= {\n");
						if (p->get) {
							fprintf(f, "\t\t\t\t.add\t= add%s_%s,\n", base, i->name);
							fprintf(h, "void add%s_%s(const struct dm_table *, dm_id, struct dm_instance *, struct dm_instance_node *);\n",
								base, i->name);
						}
						if (p->set) {
							fprintf(f, "\t\t\t\t.del\t= del%s_%s\n", base, i->name);
							fprintf(h, "void del%s_%s(const struct dm_table *, dm_id, struct dm_instance *, struct dm_instance_node *);\n",
								base, i->name);
						}
						fprintf(f, "\t\t\t},\n");
					}

					p = p->items;
				} else
					fprintf(f, "\t\t\t.type\t= T_TOKEN,\n");

				fprintf(f, "\t\t\t.u.t = {\n");
				fprintf(f, "\t\t\t\t.table\t= &keyword_%d_tab,\n", p->id);
				if (max == INT_MAX)
					fprintf(f, "\t\t\t\t.max\t= INT_MAX\n");
				else
					fprintf(f, "\t\t\t\t.max\t= %d\n", max);
				fprintf(f, "\t\t\t},\n");
				
			} else {
				fprintf(f, "\t\t\t.type\t= %s,\n", t_types[i->type]);
				if (i->type == T_STR) {
					if (i->max != 0 && i->max != INT_MAX) {
						fprintf(f, "\t\t\t.u.l\t= {\n");
						fprintf(f, "\t\t\t\t.max\t= %d,\n", i->max);
						fprintf(f, "\t\t\t},\n");
					}
				} else if (i->type == T_INT || i->type == T_UINT) {
					fprintf(f, "\t\t\t.u.l\t= {\n");
					if (i->min != 0)
						fprintf(f, "\t\t\t\t.min\t= %d,\n", i->min);
					if (i->max == INT_MAX)
						fprintf(f, "\t\t\t\t.max\t= INT_MAX,\n");
					else
						fprintf(f, "\t\t\t\t.max\t= %d,\n", i->max);
					fprintf(f, "\t\t\t},\n");
				} else if (i->type == T_COUNTER) {
					fprintf(f, "\t\t\t.u.counter_ref\t= %d,\n", getNodeId(n, i->count_ref));
				} else if (i->type == T_ENUM) {
					char *s, *e, *p;
					int n = 0;

					fprintf(f, "\t\t\t.u.e\t= { .data = \"");
					fprintf(h, "typedef enum {\n");
					e = i->cenum;
					while (e) {
						s = strchr(e, ',');
						if (s)
							*s++ = '\0';
						fprintf(f, "%s", e);
						if (s)
							fprintf(f, "\\000");

						for (p = e; *p; p++)
							if (*p == '-' || *p == '+' || *p == ' ' || *p == '.')
								*p = '_';
						fprintf(h, "\tcwmp__%s_%s_%s,\n", base, i->alias, e);

						e = s;
						n++;
					}
					fprintf(f, "\", .cnt = %d },\n", n);
					fprintf(h, "} cwmp__%s_%s_e;\n", base, i->alias);
				}
				if (i->type != T_COUNTER) {
					if (i->get || i->set) {
						fprintf(f, "\t\t\t.fkts.value\t= {\n");
						if (i->get) {
							fprintf(f, "\t\t\t\t.get\t= get%s_%s,\n", base, i->name);
							fprintf(h, "DM_VALUE get%s_%s(const struct dm_value_table *, dm_id, const struct dm_element *, DM_VALUE);\n",
								base, i->name);
						}
						if (i->set) {
							fprintf(f, "\t\t\t\t.set\t= set%s_%s\n", base, i->name);
							fprintf(h, "int set%s_%s(struct dm_value_table *, dm_id, const struct dm_element *, DM_VALUE *, DM_VALUE);\n",
								base, i->name);
						}
						fprintf(f, "\t\t\t},\n");
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

	for (i = n; i; i = i->next) {
		struct node *p = i->items;

		if (i->name[0] == '{')
			continue;

		if (p && p->name[0] == '{') {
			if (p->get)
				fprintf(stubs, "DMInstanceStub(add%s_%s);\n", base, i->name);
			if (p->set)
				fprintf(stubs, "DMInstanceStub(del%s_%s);\n", base, i->name);
		} else {
			if (i->get)
				fprintf(stubs, "DMGetStub(get%s_%s);\n", base, i->name);
			if (i->set)
				fprintf(stubs, "DMSetStub(set%s_%s);\n", base, i->name);
		}
	}
}

void genTablef(FILE *f, FILE *h, FILE *stubs, struct node *n, const char *base, int cntCntr)
{
	struct node *p;
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

		genTablef(f, h, stubs, p, buf, cnt);
		p = p->next;
	}

	if (n->items)
		genKeywordTab(f, h, stubs, n->items, base, cntCntr, n);
}

void dumpNodes(FILE *f, struct node *n, const char *base, const char *id_base)
{
	char nt[128];
	char idb[128];
	struct node *p;

	if (!n)
		return;

	/* printf("%s   -> %s (%p)\n",n->name, base, n->items);*/
	p = n->items;

	if (base[0] != '\0') {
		fprintf(f, "%s,%s", id_base, base);
		if (p) {
			fprintf(f, ".");
			if (n->alias[0] != '{')
				fprintf(f, ",%s", n->alias);
		} else {
			if (n->get || n->set)
				fprintf(f, ",,%d,%d", n->get, n->set);
		}
		fprintf(f, "\n");
	}

	while (p) {
		snprintf(nt, 128, "%s.%s", base, p->name);
		if (p->name[0] != '{')
			snprintf(idb, 128, "%s.%d", id_base, p->tid);
		else
			snprintf(idb, 128, "%s.i", id_base);
		dumpNodes(f, p, nt, idb);
		p = p->next;
	}
}

void dumpNodes2xml(FILE *f, struct node *n, const char *ident)
{
	char idb[128];
	struct node *p;

	if (!n)
		return;

	p = n->items;

	while (p) {
		if (p->items) {
			if (p->name[0] != '{') {
				fprintf(f, "%s<%s>\n", ident, p->name);
				snprintf(idb, 128, "%s   ", ident);
				dumpNodes2xml(f, p, idb);
				fprintf(f, "%s</%s>\n", ident, p->name);
			} else
				dumpNodes2xml(f, p, ident);
		} else
			fprintf(f, "%s<%s />\n", ident, p->name);
		p = p->next;
	}
}

struct node *node;

void process_line(char **csv)
{
	int flags;
	struct node *n = NULL;
	char *alias = NULL;
	int action = DM_NONE;
	long min;
	long max;


	flags = 0;
	if (*csv[CSV_WRITE_FLAG] == 'R' || *csv[CSV_WRITE_FLAG] == 'O' || *csv[CSV_WRITE_FLAG] == 'C')
		flags |= F_WRITE;
	if (*csv[CSV_READ_FLAG] == 'R' || *csv[CSV_READ_FLAG] == 'O' || *csv[CSV_READ_FLAG] == 'C')
		flags |= F_READ;

	if (csv[CSV_SYSTEM_FLAG][SFLAG_SYSTEM] != '\0') {
		if (csv[CSV_SYSTEM_FLAG][SFLAG_SYSTEM] == 'S')
			flags |= F_SYSTEM;
		else if (csv[CSV_SYSTEM_FLAG][SFLAG_SYSTEM] == 'i')
			flags |= F_INTERNAL;
		else if (csv[CSV_SYSTEM_FLAG][SFLAG_SYSTEM] == 'V')
			flags |= F_VERSION;

		if (csv[CSV_SYSTEM_FLAG][SFLAG_INDEX] != '\0') {
			if (csv[CSV_SYSTEM_FLAG][SFLAG_INDEX] == 'i')
				flags |= F_INDEX;
			
			if (csv[CSV_SYSTEM_FLAG][SFLAG_NOTIFY] != '\0') {
				/* forced notification */
				if (csv[CSV_SYSTEM_FLAG][SFLAG_NOTIFY] == 'F')
					flags |= F_NTFY;
				
				/* no active notification */
				if (csv[CSV_SYSTEM_FLAG][SFLAG_NOTIFY] == 'N')
					flags |= F_NO_NTFY;

				if (csv[CSV_SYSTEM_FLAG][SFLAG_MAP_ID] != '\0') {
					if (csv[CSV_SYSTEM_FLAG][SFLAG_MAP_ID] == 'M')
						flags |= F_MAP_ID;
				}
			}
		}
	}

	//		printf("flags: %x, W: '%s', R: '%s'\n", flags, csv[CSV_WRITE_FLAG], csv[CSV_READ_FLAG]);

	if (csv[CSV_ACTION] && *csv[CSV_ACTION]) {
		action = map_string(csv[CSV_ACTION], action_map, sizeof(action_map) / sizeof(struct string_map), mapcasecmp);
		if (action < 0) {
			fprintf(stderr, "Warning: unknown action: '%s'\n", csv[CSV_ACTION]);
			action = DM_NONE;
		}
	}

	min = 0;
	max = INT_MAX;

	if (csv[CSV_KEY] && csv[CSV_DATA_TYPE]) {
		char *s;

		s = strrchr(csv[CSV_DATA_TYPE], '[');
		if (s) {
			char *n;

			*s++ = '\0';
			n = s;
			while (*s && *s != ':' && *s != ']')
				s++;
			if (*s == ':') {
				*s++ = '\0';
				min = atol(n);
				n = s;
				if (*n != ']') {
					while (*s && *s != ':' && *s != ']')
						s++;
					*s++ = '\0';
					max = atol(n);
				}
			}
		}
	}

	printf("Key: '%s', Type: '%s', min: %ld, max: %ld\n", csv[CSV_KEY], csv[CSV_DATA_TYPE], min, max);

	if (csv[CSV_DATA_TYPE] && (strcasecmp(csv[CSV_DATA_TYPE], "object") == 0 || strlen(csv[CSV_DATA_TYPE]) == 0)) {
		char *s;

		/* object instances are always '.' terminated */
		int pos = strlen(csv[CSV_KEY])-1;
		if (csv[CSV_KEY][pos] == '.')
			csv[CSV_KEY][pos] = '\0';
		

		s = strrchr(csv[CSV_KEY], '.');
		if (s)
			s++;
		else
			s = csv[CSV_KEY];

		alias = csv[CSV_ALIAS];
		if (!alias || !alias[0])
			alias = s;
		node = addObject(findNode(head, csv[CSV_KEY]), s, alias, atoi(csv[CSV_GET_FLAG]), atoi(csv[CSV_SET_FLAG]));
		node->flags = flags & ~(F_READ | F_WRITE);
		node->action = action;
		node->max = max;
		node->min = min;
	}
	else if (csv[CSV_KEY] && csv[CSV_DATA_TYPE]) {
		char *s;
		int type;
		char *cenum = NULL;

		type = T_FKT;
		if (strncasecmp(csv[CSV_DATA_TYPE], "unsignedInt64", 13) == 0)
			type = T_UINT64;
		else if (strncasecmp(csv[CSV_DATA_TYPE], "int64", 5) == 0)
			type = T_INT64;
		else if (strncasecmp(csv[CSV_DATA_TYPE], "unsignedInt", 11) == 0)
			type = T_UINT;
		else if (strncasecmp(csv[CSV_DATA_TYPE], "int", 3) == 0)
			type = T_INT;
		else if (strncasecmp(csv[CSV_DATA_TYPE], "bool", 4) == 0)
			type = T_BOOL;
		else if (strncasecmp(csv[CSV_DATA_TYPE], "selector", 4) == 0)
			type = T_SELECTOR;
		else if (strncasecmp(csv[CSV_DATA_TYPE], "string", 6) == 0) {
			type = T_STR;
			s = strrchr(csv[CSV_DATA_TYPE], ')');
			if (s) {
				int mult = 1;

				*(s--) = '\0';
				if (*s == 'K' || *s == 'k')
					mult = 1024;
				s = strrchr(csv[CSV_DATA_TYPE], '(');
				if (s)
					max = atoi(s+1) * mult;
			}
		}
		else if (strncasecmp(csv[CSV_DATA_TYPE], "ipv4", 6) == 0)
			type = T_IPADDR4;
		else if (strncasecmp(csv[CSV_DATA_TYPE], "binary", 6) == 0)
			type = T_BINARY;
		else if (strncasecmp(csv[CSV_DATA_TYPE], "base64", 6) == 0)
			type = T_BASE64;
		else if (strncasecmp(csv[CSV_DATA_TYPE], "dateTime", 8) == 0)
			type = T_DATE;
		else if (strncasecmp(csv[CSV_DATA_TYPE], "enum", 4) == 0) {
			type = T_ENUM;

			if (csv[CSV_ALIAS] && *csv[CSV_ALIAS])
				alias = csv[CSV_ALIAS];

			s = strrchr(csv[CSV_DATA_TYPE], ')');
			if (s) {
				*(s--) = '\0';
				s = strrchr(csv[CSV_DATA_TYPE], '(');
				if (s)
					cenum = strdup(++s);
			}
		} else if (strncasecmp(csv[CSV_DATA_TYPE], "pointer", 7) == 0) {
			type = T_POINTER;
			flags |= F_NO_NTFY;
		} else
			printf("unknown field type: %s\n", csv[CSV_DATA_TYPE]);

		s = strrchr(csv[CSV_KEY], '.');
		if (s)
			s++;
		else
			s = csv[CSV_KEY];

		if (strncasecmp("count", csv[CSV_COUNT_REF], 5) == 0) {
			char *ref, *e;
			
			ref = strchr(csv[CSV_COUNT_REF], '(');
			e = strchr(csv[CSV_COUNT_REF], ')');

			if (!ref || !e)
				printf("Invalid count(..) format: %s\n", csv[CSV_COUNT_REF]);
			else {
				n = addNode(findNode(head, csv[CSV_KEY]), s, NULL, 0, 0);
				if (n) {
					*e = '\0';
					ref++;
					n->count_ref = strdup(ref);
					type = T_COUNTER;
				}
			}
		} else
			n = addNode(node, s, alias, atoi(csv[CSV_GET_FLAG]), atoi(csv[CSV_SET_FLAG]));
		if (n) {
			n->type = type;
			n->max = max;
			n->min = min;
			n->flags = flags;
			n->cenum = cenum;
			n->action = action;
		}
	}
}

int field = 0;
char **csv;
int in_quote = 0;
int len;
char csv_buf[4096];
int buf_ofs;

int process_csv_line(char *line)
{
	char *buf;

	if (!field) {
		csv = malloc(sizeof(char *) * 20);
		memset(csv, 0, sizeof(char *) * 20);
		len = strlen(line);
		memcpy(&csv_buf, line, len);
		csv_buf[len] = '\0';
		buf = csv_buf;
	} else {
		len += strlen(line) + 1;
		if (len > 4096) {
			printf("Error: CSV line too long\n");
			exit(-1);
		}
		buf = csv_buf + buf_ofs;
		strcat(buf, line);
	}

	while (buf && *buf && field < 20) {
		int l;
		char *s;

		s = buf;
		while (*s) {
			if (*s == '"')
				in_quote ^= 1;
			if (!in_quote && *s == ',') {
				*(s++) = '\0';
				break;
			}
			s++;
		}
		if (in_quote) {
			buf_ofs = buf - csv_buf;
			in_quote = 0;
			return 0;
		}

		if (*buf == '"')
			buf++;
		l = strlen(buf);
		if (l && buf[l - 1] == '"')
			buf[l - 1] = '\0';

		csv[field] = buf;
		field++;
		buf = s;
	}

	process_line(csv);
	free(csv);
	field = 0;
	len = 0;

	return 0;
}

int main(int argc, char **argv)
{
	FILE *inf, *f, *h, *stubs;
	char buf[4096];

	if (argc != 2) {
		printf("Usage: tokenizer <file>\n");
		return 1;
	}

	inf = fopen(argv[1], "r");
	if (!inf) {
		printf("Error opening file %s (%m)\n", argv[1]);
		return 1;
	}

	head = malloc(sizeof(struct node));
	memset(head, 0, sizeof(struct node));
	head->name = strdup(".");
	head->append = &head->items;

	while (!feof(inf)) {
		int set, get;
		char *s;

		if (fgets(buf, 1023, inf) == NULL)
			break;

		chomp(buf);
		if (!*buf || *buf == '#')
			continue;

		process_csv_line(buf);
	}
	fclose(inf);

	stubs = fopen("p_table_stubs.c", "w");
	fprintf(stubs, "#include <stdlib.h>\n\n");
	fprintf(stubs, "#include <limits.h>\n\n");
	fprintf(stubs, "#include \"dm.h\"\n");

	fprintf(stubs, "#include \"dm_token.h\"\n");
	fprintf(stubs, "#include \"dm_action_table.h\"\n");
	fprintf(stubs, "#include \"dm_fkt_stubs.c\"\n");
	fprintf(stubs, "#include \"p_table.h\"\n\n");

	f = fopen("p_table.c", "w");
	fprintf(f, "#include <stdlib.h>\n\n");
	fprintf(f, "#include <limits.h>\n\n");
	fprintf(f, "#include \"dm.h\"\n");

	fprintf(f, "#include \"dm_token.h\"\n");
	fprintf(f, "#include \"p_table.h\"\n\n");

	h = fopen("p_table.h", "w");
	fprintf(h, "#ifndef __P_TABLE_H\n");
	fprintf(h, "#define __P_TABLE_H\n\n");

	genTablef(f, h, stubs, head, "", 0);
	fclose(f);
	fclose(stubs);

	fprintf(h, "\n#endif\n");
	fclose(h);

	//	dumpNodes2xml(stderr, head, "");

	return 0;
}
