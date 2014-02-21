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

#include "tr069d.h"
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

struct soap_attr_cb_param {
	struct soap *soap;
	struct ParameterAttributeStructArray *pl;
	struct cwmp__ParameterAttributeStruct *pv;

	char prefix[512];
	int  pos;
	int  prefix_pos[TR069_SELECTOR_LEN];
};

static int attr_walk_cb(void *userData, CB_type type, tr069_id id,
			const struct tr069_element *elem, const DM_VALUE value)
{
	struct soap_attr_cb_param *w = (struct soap_attr_cb_param *)userData;

	debug(": ev: %s, %s, %s, %d, %d\n", cb_ev_map[type], w->prefix, elem->key, w->pos, w->prefix_pos[w->pos]);

	switch (type) {
	case CB_table_start:
	case CB_object_start: {
		int len;

		len = snprintf(w->prefix + w->prefix_pos[w->pos], sizeof(w->prefix) - w->prefix_pos[w->pos],
			       "%s.", elem->key);
		w->prefix_pos[w->pos + 1] = w->prefix_pos[w->pos] + len;
		w->pos++;

		break;
	}
	case CB_object_instance_start: {
		int len;

		len = snprintf(w->prefix + w->prefix_pos[w->pos], sizeof(w->prefix) - w->prefix_pos[w->pos],
			       "%hu.", id);
		w->prefix_pos[w->pos + 1] = w->prefix_pos[w->pos] + len;
		w->pos++;
		break;
	}

	case CB_table_end:
	case CB_object_end:
	case CB_object_instance_end:
		w->pos--;
		w->prefix[w->prefix_pos[w->pos]] = '\0';
		break;

	case CB_element: {
		struct cwmp__ParameterAttributeStruct *pv;

		if (!(w->pl->__size % BLOCK_ALLOC))
			w->pv = realloc(w->pv, sizeof(struct cwmp__ParameterAttributeStruct) * (BLOCK_ALLOC + w->pl->__size));
		if (!w->pv)
			return 0;

		pv = w->pv + w->pl->__size;
		memset(pv, 0, sizeof(struct cwmp__ParameterAttributeStruct));
		w->pl->__size++;

		pv->Name = soap_malloc(w->soap, strlen(w->prefix) + strlen(elem->key) + 1);
		if (pv->Name) {
			strcpy(pv->Name, w->prefix);
			strcat(pv->Name, elem->key);
		}
		pv->Notification = value.notify & 0x0003;
		break;
	}

	default:
		break;
	}

	return 1;
}

static DM_RESULT soap_get_attr_cb(void *data,
				  const tr069_selector sel __attribute__ ((unused)),
				  const struct tr069_element *elem,
				  const DM_VALUE val)
{
	struct soap_attr_cb_param *w = (struct soap_attr_cb_param *)data;
	struct cwmp__ParameterAttributeStruct *pv;

	if (!elem)
		return DM_VALUE_NOT_FOUND;

	pv = w->pv + w->pl->__size;
	w->pl->__size++;

	w->pv->Notification = val.notify & 0x0003;

	return DM_OK;
}

int cwmp__GetParameterAttributes(struct soap                         *soap,
                                struct ParameterNamesArray           ParameterNames,
                                struct ParameterAttributeStructArray *ParameterList)
{
	int  i;
	struct soap_attr_cb_param cbp;

	ENTER();

	memset(&cbp, 0, sizeof(cbp));
	cbp.soap = soap;
	cbp.pl = ParameterList;

	for (i = 0; i <  ParameterNames.__size; i++) {
		int len;
		int recursive = 0;
		tr069_selector sel;

		len = strlen(ParameterNames.__ptr[i]);
		if (ParameterNames.__ptr[i][len - 1] == '.') {
			ParameterNames.__ptr[i][--len] = '\0';
			recursive = 1;
		}

		if (!tr069_name2sel(ParameterNames.__ptr[i], &sel)) {
			free(cbp.pv);
			cwmp_fault(soap, 9005, "Invalid parameter name");
			EXIT();
			return SOAP_FAULT;
		}

		if (recursive) {
			strcpy(cbp.prefix, ParameterNames.__ptr[i]);
			strcat(cbp.prefix, ".");

			if (!tr069_walk_by_selector_cb(sel, TR069_SELECTOR_LEN, &cbp, attr_walk_cb)) {
				free(cbp.pv);
				cwmp_fault(soap, 9005, "Invalid parameter name");
				EXIT();
				return SOAP_FAULT;
			}
		} else {
			struct cwmp__ParameterAttributeStruct *pv;

			if (!(cbp.pl->__size % BLOCK_ALLOC))
				cbp.pv = realloc(cbp.pv, sizeof(struct cwmp__ParameterAttributeStruct) * (BLOCK_ALLOC + cbp.pl->__size));
			if (!cbp.pv) {
				free(cbp.pv);
				cwmp_fault(soap, 9004, "Resources exceeded");
				EXIT();
				return SOAP_FAULT;
			}

			pv = cbp.pv + cbp.pl->__size;
			memset(pv, 0, sizeof(struct cwmp__ParameterAttributeStruct));
			pv->Name = ParameterNames.__ptr[i];

			if (tr069_get_value_by_selector_cb(sel, T_ANY, &cbp, soap_get_attr_cb) != DM_OK) {
				free(cbp.pv);
				cwmp_fault(soap, 9005, "Invalid parameter name");
				EXIT();
				return SOAP_FAULT;
			}
		}
	}

	ParameterList->__ptrParameterAttributeStruct =
		soap_malloc(soap, sizeof(struct cwmp__ParameterAttributeStruct) * ParameterList->__size);
	if (!ParameterList->__ptrParameterAttributeStruct) {
		free(cbp.pv);
		cwmp_fault(soap, 9004, "Resources exceeded");
		EXIT();
		return SOAP_FAULT;
	}
	memcpy(ParameterList->__ptrParameterAttributeStruct, cbp.pv, sizeof(struct cwmp__ParameterAttributeStruct) * ParameterList->__size);
	free(cbp.pv);

	EXIT();
	return SOAP_OK;
}

int cwmp__SetParameterAttributes(struct soap                                 *soap __attribute__ ((unused)),
				 struct SetParameterAttributesStructArray    ParameterList,
				 struct cwmp__SetParameterAttributesResponse *result __attribute__ ((unused)))
{
	printf("ParameterList: %d\n", ParameterList.__size);

	for (int i = 0; i < ParameterList.__size; i++) {
		int len;
		int recursive = 0;
		tr069_selector sel;

		len = strlen(ParameterList.__ptrSetParameterAttributesStruct[i].Name);
		if (ParameterList.__ptrSetParameterAttributesStruct[i].Name[len - 1] == '.') {
			ParameterList.__ptrSetParameterAttributesStruct[i].Name[--len] = '\0';
			recursive = 1;
		}

		if (!tr069_name2sel(ParameterList.__ptrSetParameterAttributesStruct[i].Name, &sel)) {
			cwmp_fault(soap, 9005, "Invalid Parameter Name");
			return SOAP_FAULT;
		}

		if (ParameterList.__ptrSetParameterAttributesStruct[i].NotificationChange) {
			DM_RESULT r;

			if (!recursive)
				r = tr069_set_notify_by_selector(sel, 0, ParameterList.__ptrSetParameterAttributesStruct[i].Notification);
			else
				r = tr069_set_notify_by_selector_recursive(sel, 0, ParameterList.__ptrSetParameterAttributesStruct[i].Notification);

			if (r != DM_OK) {
				cwmp_fault(soap, 9009, "Notification request rejected");
				return SOAP_FAULT;
			}
		}
	}

	tr069_save();

	return SOAP_OK;
}
