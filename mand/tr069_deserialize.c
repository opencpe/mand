#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/param.h>

#include "expat.h"
#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_store_priv.h"
#include "tr069_notify.h"
#include "tr069_deserialize.h"
#include "tr069_strings.h"
#include "tr069_luaif.h"
#include "tr069_cfgversion.h"
#include "tr069_index.h"

#define SDEBUG
#include "debug.h"

//#define XML_DEBUG
#if defined(XML_DEBUG)
#define xml_debug(format, ...) fprintf (stderr, format, ## __VA_ARGS__)
#else
#define xml_debug(format, ...) do {} while (0)
#endif

static uint16_t flags;

struct tr069_enum notify_attr = {
	.data = "None\000Passive\000Active",
	.cnt = 3
};

#define XML_VALID   (1 << 0)
#define XML_ESCAPED (1 << 1)
#define XML_UPGRADE (1 << 2)

struct XMLstate {
	char *base;
	const struct tr069_element *element;
	DM_VALUE *value;
	int flags;
	char *text;
	struct tr069_instance *inst;
	struct tr069_instance_node *node;
};

static void XMLCALL
startElement(void *userData, const char *name, const char **atts)
{
	const struct tr069_element *kw = NULL;
	DM_VALUE *val = NULL;

	struct XMLstate **state = userData;

	const char *base = (*state)->base;
	int valid = ((*state)->flags & XML_VALID) == XML_VALID;
	const struct tr069_element *element = (*state)->element;
	DM_VALUE *value = (*state)->value;

	int xid = 0;
	int ntfy = 0;
	tr069_id id;

	(*state)++;
	memset(*state, 0, sizeof(struct XMLstate));

	for (int i = 0; atts[i]; i += 2) {
		if (strcasecmp("instance", atts[i]) == 0) {
			xml_debug("%s: instance: %s\n", name, atts[i + 1]);
			xid = atoi(atts[i + 1]);
			break;
		}
		else if (strcasecmp("notify", atts[i]) == 0) {
			xml_debug("%s: notify: %s\n", name, atts[i + 1]);
			ntfy = tr069_enum2int( &notify_attr, atts[i + 1]);
		}
		else if (strcasecmp("encoding", atts[i]) == 0) {
			xml_debug("%s: encoding: %s\n", name, atts[i + 1]);
			if (strcasecmp(atts[i+1], "escaped") == 0)
				(*state)->flags |= XML_ESCAPED;
		}
		else if (strcasecmp("version", atts[i]) == 0) {
			xml_debug("%s: config version: %s\n", name, atts[i + 1]);
			tr069_set_cfg_version(atoi(atts[i + 1]));
		}
	}

	if (xid != 0)
		asprintf(&(*state)->base, "%s.%s.%d", base, name, xid);
	else
		asprintf(&(*state)->base, "%s.%s", base, name);

	if (valid) {
		const struct tr069_table *table = element->u.t.table;

		id = tr069_get_element_id_by_name(name, strlen(name), table);
		if (id != TR069_ERR) {
			kw = &(table->table[id - 1]);
			val = tr069_get_value_ref_by_id(DM_TABLE(*value), id);
			(*state)->flags |= XML_VALID;
		} else {
			printf("Element '%s' not found in table '%s'\n", name, element->key);
			valid = 0;
		}
	}

	if (!valid || !((*state)->flags & XML_VALID)) {
		debug("enter invalid: %s\n", (*state)->base);
		return;
	}

	if (flags & DS_VERSIONCHECK &&
	    kw->flags & F_VERSION &&
	    tr069_get_cfg_version() != CFG_VERSION) {
		(*state)->flags |= XML_UPGRADE;

		lua_pushinteger(lua_environment, CFG_VERSION);
		lua_pushinteger(lua_environment, tr069_get_cfg_version());
		if (fp_Lua_function("fncPreVersionCheck", 2))
			debug("(): Error during Lua function execution");
	}

	xml_debug("enter: %s = %p, (%p, %p)\n", name, *state, kw, val);

	(*state)->element = kw;
	if (kw->type == T_OBJECT) {
		struct tr069_instance *inst = DM_INSTANCE(*val);
		struct tr069_instance_node *node = NULL;

		/** FIXME: this should be easier */
		if (xid > 0)
			node = tr069_get_instance_node_by_id(inst, xid);
		if (!node) {
			tr069_selector basesel;

			tr069_selcpy(basesel, DM_TABLE(*value)->id);
			tr069_selcat(basesel, id);

			node = tr069_add_instance(kw, inst, basesel, xid);
			dm_assert(node);

			if (flags & DS_USERCONFIG) {
				val->flags |= DV_UPDATED;
				DM_parity_update(*val);
				node->table.flags |= DV_UPDATED;
				DM_parity_update(node->table);
			}
		}

		val = &node->table;

		(*state)->inst = inst;
		(*state)->node = node;

	} else if (kw->type == T_TOKEN) {
		if (DM_TABLE(*val) == NULL) {
			set_DM_TABLE(*val, tr069_alloc_table(kw->u.t.table, DM_TABLE(*value)->id, id));

			if (flags & DS_USERCONFIG)
				val->flags |= DV_UPDATED;
			xml_debug("adding table for token \"%s\" with %d elements: %p\n", name,
				  kw->u.t.table->size, DM_TABLE(*val));
			DM_parity_update(*val);
		}
	}
	(*state)->value = val;
	if (ntfy >= 0)
		set_notify_single_slot_element(kw, (*state)->value, 0, ntfy);
}

static void string_unescape(char *text, const char *s, int len)
{
	int in_c = 0;
	char c;
	char *d = text + strlen(text);

	while (len) {
		if (!in_c) {
			if (*s == '\\') {
				in_c++;
				c = '\0';
			} else
				*d++ = *s;
		} else {
			if (*s >= '0' && *s <= '7') {
				c = (c << 3) | (*s - '0');
				in_c++;
			} else
				/* abort decoding on error */
				break;
			if (in_c == 4) {
				*d++ = c;
				in_c = 0;
			}
		}
		s++;
		len--;
	}
	*d = '\0';
}

static void XMLCALL
charElement(void *userData, const XML_Char *s, int len)
{
	char buf[1024];

	struct XMLstate **state = userData;

	if (len > 1024)
		len = 1023;
	memcpy(buf, s, len);
	buf[len] = '\0';

	if (!(*state)->text) {
		(*state)->text = calloc(len + 1, 1);
	} else
		(*state)->text = realloc((*state)->text, strlen((*state)->text) + len + 1);

	if (!(*state)->text)
		return;

	if (((*state)->flags & XML_ESCAPED) == XML_ESCAPED)
		string_unescape((*state)->text, s, len);
	else
		strncat((*state)->text, s, len);
}

static void handleElement(struct XMLstate *state)
{
	DM_RESULT res;

	xml_debug("handling data: %s\n", state->text ? : "NOTHING");

	res = tr069_string2value(state->element, state->text, flags & DS_USERCONFIG, state->value);
#ifdef XML_DEBUG
	if (res != DM_OK)
		xml_debug("tr069_string2value returned %d (DM_RESULT)\n", res);
#endif
}

static void XMLCALL
endElement(void *userData, const char *name __attribute__ ((unused)))
{
	struct XMLstate **state = userData;

	if (((*state)->flags & XML_VALID) == XML_VALID) {
		handleElement(*state);

		if ((*state)->inst)
			update_instance_node_index((*state)->node);
	} else {
		debug("handle invalid: %s = '%s'\n", (*state)->base, (*state)->text ? : "NOTHING");
	}

	if (((*state)->flags & XML_UPGRADE) == XML_UPGRADE) {
		lua_pushinteger(lua_environment, CFG_VERSION);
		lua_pushinteger(lua_environment, tr069_get_cfg_version());
		if (fp_Lua_function("fncPostVersionCheck", 2))
			debug("(): Error during Lua function execution");
	}

	free((*state)->text);
	free((*state)->base);
	(*state)--;

	xml_debug("exit: %s = %p\n", name, *state);
}

int tr069_deserialize_store(FILE *stream, int _flags)
{
	char buf[BUFSIZ];
	XML_Parser parser = XML_ParserCreate(NULL);
	int done;
	int old_flags;
	int r = 0;

	const struct tr069_element element = { .type = T_TOKEN, .u.t.table = &dm_root };
	DM_VALUE tr069_value_root;

	struct XMLstate stateStk[10] = { { .element = &element, .value = &tr069_value_root, .base = "", .flags = XML_VALID } };
	struct XMLstate *state = &stateStk[0];

	old_flags = flags;
	flags = _flags;

	if (!tr069_value_store)
		tr069_value_store = tr069_alloc_table(&dm_root, (tr069_selector){ 0, }, 0);

	set_DM_TABLE(tr069_value_root, tr069_value_store);
	DM_parity_update(tr069_value_root);

	XML_SetUserData(parser, &state);
	XML_SetElementHandler(parser, startElement, endElement);
	XML_SetCharacterDataHandler(parser, charElement);

	do {
		size_t len = fread(buf, 1, sizeof(buf), stream);
		done = len < sizeof(buf);
		if (XML_Parse(parser, buf, len, done) == XML_STATUS_ERROR) {
			fprintf(stderr,
				"%s at line %d\n",
				XML_ErrorString(XML_GetErrorCode(parser)),
				XML_GetCurrentLineNumber(parser));
			r = 1;
			break;
		}
	} while (!done);
	XML_ParserFree(parser);
	flags = old_flags;

	return r;
}

int tr069_deserialize_file(const char *fname, int _flags)
{
	int r = 1;

	debug("deserialize %s", fname);

	FILE *fin = fopen(fname, "r");
	if (fin) {
		r = tr069_deserialize_store(fin, _flags);
		fclose(fin);
	}

	return r;
}

int tr069_deserialize_directory(const char *dir, int _flags)
{
	struct dirent **namelist;
	int n;
	int r = 0;

	n = scandir(dir, &namelist, 0, alphasort);
	if (n < 0) {
		/* expected error */
		if (errno != ENOENT)
			perror("scandir");
		return 1;
	}

	for (int i = 0; i < n; i++) {
		if (namelist[i]->d_name[0] != '.') {
			char fname[MAXPATHLEN];

			snprintf(fname, sizeof(fname), "%s/%s", dir, namelist[i]->d_name);
			r |= tr069_deserialize_file(fname, _flags);
		}
		free(namelist[i]);
	}
	free(namelist);

	return r;
}
