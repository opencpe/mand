/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2008 Travelping GmbH <info@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "tr069.h"
#include "soapH.h"

#define SDEBUG
#include "debug.h"

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_strings.h"

#if defined(SDEBUG)
#define cb_ev_map_init(x)   [x] = #x
static const char *cb_ev_map[] = {
	cb_ev_map_init(CB_element),
	cb_ev_map_init(CB_table_start),
	cb_ev_map_init(CB_table_end),
	cb_ev_map_init(CB_object_start),
	cb_ev_map_init(CB_object_end),
	cb_ev_map_init(CB_object_instance_start),
	cb_ev_map_init(CB_object_instance_end),
};
#endif

#define BLOCK_ALLOC 128

struct walk_data {
	struct soap *soap;

	struct ParameterInfoStructArray *ParameterList;
	struct cwmp__ParameterInfoStruct *pi;

	char prefix[512];
	int  pos;
	int  prefix_pos[TR069_SELECTOR_LEN];
};

static int walk_cb(void *userData, CB_type type, tr069_id id  __attribute__ ((unused)),
		   const struct tr069_element *elem, const DM_VALUE value)
{
	struct walk_data *w = (struct walk_data *)userData;
	int element = w->ParameterList->__size;

	debug(": ev: %s, %s, %s, %d, %d\n", cb_ev_map[type], w->prefix, elem->key, w->pos, w->prefix_pos[w->pos]);

	switch (type) {
	case CB_table_start:
	case CB_object_start:
	case CB_object_instance_start:
	case CB_element:
		if (!(element % BLOCK_ALLOC))
			w->pi = realloc(w->pi, sizeof(struct cwmp__ParameterInfoStruct) * (w->ParameterList->__size + BLOCK_ALLOC));
		if (!w->pi)
			return 0;
		memset(&w->pi[element], 0, sizeof(struct cwmp__ParameterInfoStruct));
		w->pi[element].Writable = (elem->flags & F_WRITE) != 0;

		w->ParameterList->__size++;
		break;

	default:
		break;
	}

	switch (type) {
	case CB_table_start:
	case CB_object_start: {
		int len;

		len = snprintf(w->prefix + w->prefix_pos[w->pos], sizeof(w->prefix) - w->prefix_pos[w->pos],
			       "%s.", elem->key);
		w->prefix_pos[w->pos + 1] = w->prefix_pos[w->pos] + len;
		w->pos++;

		w->pi[element].Name = soap_strdup(w->soap, w->prefix);
		break;
	}
	case CB_object_instance_start: {
		int len;

		len = snprintf(w->prefix + w->prefix_pos[w->pos], sizeof(w->prefix) - w->prefix_pos[w->pos],
			       "%hu.", id);
		w->prefix_pos[w->pos + 1] = w->prefix_pos[w->pos] + len;
		w->pos++;

		w->pi[element].Name = soap_strdup(w->soap, w->prefix);
		break;
	}

	case CB_table_end:
	case CB_object_end:
	case CB_object_instance_end:
		w->pos--;
		w->prefix[w->prefix_pos[w->pos]] = '\0';
		break;

	case CB_element:
		w->pi[element].Name = soap_malloc(w->soap, strlen(w->prefix) + strlen(elem->key) + 1);
		if (w->pi[element].Name) {
			strcpy(w->pi[element].Name, w->prefix);
			strcat(w->pi[element].Name, elem->key);
		}
		break;

	default:
		break;
	}

	return 1;
}

int cwmp__GetParameterNames(struct soap                     *soap,
			    xsd__string                     ParameterPath,
			    xsd__boolean                    NextLevel,
			    struct ParameterInfoStructArray *ParameterList)
{
	int len;
	int skip = 0;
	int obj;
	char *s;
	tr069_selector sb;
	struct walk_data w;
	struct cwmp__ParameterInfoStruct *pi;

	memset(&w, 0, sizeof(w));
	w.soap = soap;
	w.ParameterList = ParameterList;

	if (!ParameterPath || !*ParameterPath)
		ParameterPath = "InternetGatewayDevice.";

	len = strlen(ParameterPath);
	obj = (ParameterPath[len - 1] == '.');
	if (NextLevel && !obj) {
		cwmp_fault(soap, 9005, "Invalid Parameter Name");
		return SOAP_FAULT;
	}

	ParameterPath[--len] = '\0';

	s = strrchr(ParameterPath, '.');
	if (s) {
		strncpy(w.prefix, ParameterPath, s - ParameterPath + 1);
		w.prefix_pos[0] = s - ParameterPath + 1;
	}

	if (!tr069_name2sel(ParameterPath, &sb)) {
		cwmp_fault(soap, 9005, "Invalid Parameter Name");
		return SOAP_FAULT;
	}

	if (!tr069_walk_by_selector_cb(sb, NextLevel ? 2 : TR069_SELECTOR_LEN, &w, walk_cb)) {
		cwmp_fault(soap, 9002, "Internal error");
		free(w.pi);
		return SOAP_FAULT;
	}

	pi = w.pi;
	if (NextLevel) {
		/* skip the 1st element if NextLevel = TRUE */
		w.pi++;
		w.ParameterList->__size--;
	}

	w.ParameterList->__ptrParameterInfoStruct =
		soap_malloc(soap, sizeof(struct cwmp__ParameterInfoStruct) * w.ParameterList->__size);
	if (!w.ParameterList->__ptrParameterInfoStruct) {
		cwmp_fault(soap, 9004, "Resources exceeded");
		free(pi);
		return SOAP_FAULT;
	}
	memcpy(w.ParameterList->__ptrParameterInfoStruct, w.pi,
	       sizeof(struct cwmp__ParameterInfoStruct) * w.ParameterList->__size);
	free(pi);

	return SOAP_OK;
}
