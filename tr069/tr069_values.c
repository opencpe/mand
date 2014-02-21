#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include "tr069.h"
#include "soapH.h"

#define SDEBUG
#include "debug.h"

#include "tr069d.h"
#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_cache.h"
#include "tr069_values.h"
#include "tr069_cfgsessions.h"
#include "tr069_strings.h"

void cwmp_fault(struct soap *soap,
		unsigned int code,
		char *msg)
{
        static struct _cwmp__Fault fault;
	static struct SOAP_ENV__Detail detail;

        memset(&detail, 0, sizeof(detail));
        detail.__type = SOAP_TYPE__cwmp__Fault;
        detail.__any = NULL;
        detail.fault = &fault;

        memset(&fault, 0, sizeof(fault));
        fault.FaultCode = code;
        fault.FaultString = msg;

        soap_sender_fault(soap, "CWMP fault", NULL);
	soap->fault->detail = &detail;
}

struct soap_cb_param {
	struct soap *soap;
	struct ParameterValueStructArray  *pl;
	struct cwmp__ParameterValueStruct *pv;
};

static DM_RESULT soap_get_cb(void *data,
			     const tr069_selector sel __attribute__ ((unused)),
			     const struct tr069_element *elem,
			     const DM_VALUE val)
{
	struct soap_cb_param *cbp = (struct soap_cb_param *)data;

	if (!elem)
		return DM_VALUE_NOT_FOUND;

	switch(elem->type) {
		case T_COUNTER:
		case T_UINT:
			returnUnsignedInt(cbp->soap, cbp->pv, DM_UINT(val));
			break;
		case T_INT:
			returnUnsignedInt(cbp->soap, cbp->pv, DM_INT(val));
			break;
		case T_ENUM:
			returnStrPtr(cbp->soap, cbp->pv, tr069_int2enum(&elem->u.e, DM_ENUM(val)));
			break;
		case T_STR:
			returnStrPtr(cbp->soap, cbp->pv, DM_STRING(val));
			break;
		case T_BOOL:
			returnBoolean(cbp->soap, cbp->pv, DM_BOOL(val));
			break;
		case T_DATE:
			returnDateTime(cbp->soap, cbp->pv, time2ticks(DM_TIME(val)));
			break;
		case T_TICKS:
			returnDateTime(cbp->soap, cbp->pv, DM_TICKS(val));
			break;
		case T_IPADDR4:
			returnIPv4(cbp->soap, cbp->pv, DM_IP4(val));
			break;
		default:
			return DM_INVALID_TYPE;
	}

	cbp->pv++;
	cbp->pl->__size++;

	return DM_OK;
}

int cwmp__GetParameterValues(struct soap                      *soap,
			     struct ParameterNamesArray       ParameterNames,
			     struct ParameterValueStructArray *ParameterList)
{
	int  i;
	struct soap_cb_param cbp;

	ParameterList->__ptrParameterValueStruct =
		soap_malloc(soap, sizeof(struct cwmp__ParameterValueStruct) * ParameterNames.__size);
	if (!ParameterList->__ptrParameterValueStruct) {
		cwmp_fault(soap, 9000, "out of memory");
		return SOAP_FAULT;
	}

	cbp.soap = soap;
	cbp.pl = ParameterList;
	cbp.pv = ParameterList->__ptrParameterValueStruct;

	for (i = 0; i <  ParameterNames.__size; i++) {
		tr069_selector sel;

		if (!tr069_name2sel(ParameterNames.__ptr[i], &sel))
			continue;

		cbp.pv->Name = ParameterNames.__ptr[i];
		if (tr069_get_value_by_selector_cb(sel, T_ANY, &cbp, soap_get_cb) != DM_OK) {
			/* FIXME: handle error case */
		}
	}
	return SOAP_OK;
}

static DM_RESULT soap_set_cb(void *userData,
			     const tr069_selector sel,
			     const struct tr069_element *elem,
			     struct tr069_value_table *st,
			     const void *value,
			     DM_VALUE *old_value)
{
	struct cwmp__ParameterValueStruct *p = (struct cwmp__ParameterValueStruct *)userData;
	DM_VALUE new_value;
	char *msg = NULL;
	unsigned int code = 0;
	DM_RESULT r = DM_OK;

	if (!value || !elem)
		return DM_VALUE_NOT_FOUND;

	memset(&new_value, 0, sizeof(new_value));

	printf("handling value: %p\n", value);
	switch (elem->type) {
		case T_STR:
			if (p->__typeValue != SOAP_TYPE_string &&
			    p->__typeValue != SOAP_TYPE_xsd__string) {
				code = 9006;
				msg = "Invalid parameter type";
				r = DM_INVALID_TYPE;
				break;
			}

			tr069_set_string_value(&new_value, (xsd__string)value);
			break;

		case T_UINT:
			if (p->__typeValue != SOAP_TYPE_unsignedInt &&
			    p->__typeValue != SOAP_TYPE_xsd__unsignedInt) {
				code = 9006;
				msg = "Invalid parameter type";
				r = DM_INVALID_TYPE;
				break;
			}

			set_DM_UINT(new_value, *(xsd__unsignedInt *)value);
			break;

		case T_INT:
			if (p->__typeValue != SOAP_TYPE_int &&
			    p->__typeValue != SOAP_TYPE_xsd__int) {
				code = 9006;
				msg = "Invalid parameter type";
				r = DM_INVALID_TYPE;
				break;
			}

			set_DM_INT(new_value, *(xsd__int *)value);
			break;

		case T_ENUM: {
			int i;

			if (p->__typeValue != SOAP_TYPE_string &&
			    p->__typeValue != SOAP_TYPE_xsd__string) {
				code = 9006;
				msg = "Invalid parameter type";
				r = DM_INVALID_TYPE;
				break;
			}

			i = tr069_enum2int(&elem->u.e, (xsd__string)value);
			if (i < 0) {
				printf("%s(): error converting %s to ENUM\n", __FUNCTION__, (xsd__string)value);
				code = 9007;
				msg = "Invalid Enumeration Value";
				r = DM_INVALID_VALUE;
				break;
			}
			set_DM_ENUM(new_value, i);
			break;
		}
		case T_BOOL:
			if (p->__typeValue != SOAP_TYPE_xsd__boolean) {
				code = 9006;
				msg = "Invalid parameter type";
				r = DM_INVALID_TYPE;
				break;
			}

			set_DM_BOOL(new_value, *(xsd__boolean *)value);
			break;
		case T_DATE: {
			if (p->__typeValue != SOAP_TYPE_xsd__dateTime) {
				code = 9006;
				msg = "Invalid parameter type";
				r = DM_INVALID_TYPE;
				break;
			}

			set_DM_TIME(new_value, ticks2time(*(xsd__dateTime *)value));
			break;
		}
		case T_TICKS:
			if (p->__typeValue != SOAP_TYPE_xsd__dateTime) {
				code = 9006;
				msg = "Invalid parameter type";
				r = DM_INVALID_TYPE;
				break;
			}

			set_DM_TICKS(new_value, *(xsd__dateTime *)value);
			break;

	        case T_IPADDR4: {
			int r;
			struct in_addr ip4_val;

			if (p->__typeValue != SOAP_TYPE_string &&
			    p->__typeValue != SOAP_TYPE_xsd__string) {
				code = 9006;
				msg = "Invalid parameter type";
				r = DM_INVALID_TYPE;
				break;
			}

			r = inet_pton(AF_INET, (xsd__string)value, &ip4_val);
			if (r <= 0) {
				printf("%s(): invalid IP address: %s\n", __FUNCTION__, (xsd__string)value);
				code = 9007;
				msg = "Invalid IP Address";
				r = DM_INVALID_VALUE;
				break;
			}
			set_DM_IP4(new_value, ip4_val);

			break;
		}
		default:
			code = 9006;
			msg = "Unable to Set Data Type";
			r = DM_INVALID_TYPE;
			break;
	}
	old_value->flags |= DV_UPDATE_PENDING;
	DM_parity_update(*old_value);

	cache_add(sel, p->Name, elem, st, old_value, new_value, code, msg);
	return r;
}

int cwmp__SetParameterValues(struct soap                      *soap        __attribute__ ((unused)),
			     struct ParameterValueStructArray ParameterList,
                             xsd__string                      ParameterKey __attribute__ ((unused)),
                             xsd__int                         *Status      __attribute__ ((unused)))
{
	int ret = 0;
	struct cwmp__SetParameterValuesFault *fi, *faults;
	int faults_cnt = 0;

	ENTER();

	if (getCfgSessionStatus() != CFGSESSION_INACTIVE) {
		cwmp_fault(soap, 9001, "Configuration session already in progress");
		EXIT();
		return SOAP_FAULT;
	}
	setCfgSessionStatus(CFGSESSION_ACTIVE_CWMP);

	faults = fi = (struct cwmp__SetParameterValuesFault *)soap_malloc(soap, sizeof(struct cwmp__SetParameterValuesFault) * ParameterList.__size);
	if (!fi) {
		cwmp_fault(soap, 9000 /* should be 9002? */, "out of memory");
		setCfgSessionStatus(CFGSESSION_INACTIVE);
		EXIT();
		return SOAP_FAULT;
	}

	debug("(): ParameterList: %d", ParameterList.__size);
	for (int i = 0; i < ParameterList.__size; i++) {
		int r = 0;

		debug("(): %s: %p (%d)",
		       ParameterList.__ptrParameterValueStruct[i].Name,
		       ParameterList.__ptrParameterValueStruct[i].Value,
		       ParameterList.__ptrParameterValueStruct[i].__typeValue);

		tr069_selector sel;

		if (tr069_name2sel(ParameterList.__ptrParameterValueStruct[i].Name, &sel)) {
			r = tr069_get_value_ref_by_selector_cb(sel,
							       ParameterList.__ptrParameterValueStruct[i].Value,
							       &ParameterList.__ptrParameterValueStruct[i],
							       soap_set_cb);
		} else
			r = DM_VALUE_NOT_FOUND;

		if (r != DM_OK)
			debug("(): failed to set value for %s", ParameterList.__ptrParameterValueStruct[i].Name);
		if (r == DM_VALUE_NOT_FOUND) {
			fi->ParameterName = ParameterList.__ptrParameterValueStruct[i].Name;
			fi->FaultCode = 9007;
			fi->FaultString = "Invalid Parameter Name";

			fi++;
			faults_cnt++;
		}
		ret |= r != DM_OK;
	}

	/* validate everything */
	ret |= !cache_validate();

	if (!ret) {
		/* everything ok */
		cache_apply(0);
		tr069_save();

		setCfgSessionStatus(CFGSESSION_INACTIVE);

		igd_parameters_tstamp = monotonic_time();
		EXIT();
		return SOAP_OK;
	}

	/* build and return soap fault */
	cwmp_fault(soap, 9003, "Invalid Arguments");

	struct cache_item *item;

	RB_FOREACH(item, cache, &cache) {
		if (item->code == 0)
			continue;

		fi->ParameterName = item->name;
		fi->FaultCode = item->code;
		fi->FaultString = item->msg;

		fi++;
		faults_cnt++;
	}

	cache_reset();
	struct _cwmp__Fault *fault = soap->fault->detail->fault;

	fault->SetParameterValuesFault = faults;
	fault->__sizeSetParameterValuesFault = faults_cnt;

	setCfgSessionStatus(CFGSESSION_INACTIVE);

	EXIT();
	return SOAP_FAULT;
}

static const char* dateTime2s(struct soap *soap, ticks_t n)
{
	return ticks2str(soap->tmpbuf, sizeof(soap->tmpbuf), n);
}

static int s2dateTime(struct soap *soap, const char *s, ticks_t *p)
{
	if (str2ticks(s, p) < 0)
		return soap->error = SOAP_TYPE;

	return soap->error;
}

void soap_default_xsd__dateTime(struct soap *soap __attribute__ ((unused)), ticks_t *ts)
{
	*ts = 0;
}

int soap_out_xsd__dateTime(struct soap *soap, const char *tag, int id, const ticks_t *ts, const char *type)
{
	if (soap_element_begin_out(soap, tag, soap_embedded_id(soap, id, ts, SOAP_TYPE_xsd__dateTime), type) ||
	    soap_string_out(soap, dateTime2s(soap, *ts), 0))
		return soap->error;
	return soap_element_end_out(soap, tag);
}

ticks_t *soap_in_xsd__dateTime(struct soap *soap, const char *tag, ticks_t *ts, const char *type)
{
	if (soap_element_begin_in(soap, tag, 0, NULL))
		return NULL;
	if (*soap->type &&
	    soap_match_tag(soap, soap->type, type) &&
	    soap_match_tag(soap, soap->type, ":dateTime")) {
		soap->error = SOAP_TYPE;
		soap_revert(soap);
		return NULL;
	}
	ts = (ticks_t *)soap_id_enter(soap, soap->id, ts, SOAP_TYPE_xsd__dateTime, sizeof(ticks_t), 0, NULL, NULL, NULL);
	if (*soap->href)
		ts = (ticks_t *)soap_id_forward(soap, soap->href, ts, 0, SOAP_TYPE_xsd__dateTime, 0, sizeof(ticks_t), 0, NULL);
	else if (ts) {
		if (s2dateTime(soap, soap_value(soap), ts))
			return NULL;
	}
	if (soap->body && soap_element_end_in(soap, tag))
		return NULL;
	return ts;
}

