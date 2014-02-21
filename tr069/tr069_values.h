#ifndef __TR069_VALUES_H
#define __TR069_VALUES_H

#include "tr069.h"
#include "soapH.h"

static inline void returnStrPtr(struct soap *soap __attribute__ ((unused)),
				struct cwmp__ParameterValueStruct *p, const char *s)
{
	p->__typeValue = SOAP_TYPE_xsd__string;
	p->Value = s;
}

static inline void returnIPv4(struct soap *soap,
			      struct cwmp__ParameterValueStruct *p,
			      const struct in_addr i)
{
	p->__typeValue = SOAP_TYPE_xsd__string;
	if ((p->Value = soap_malloc(soap, INET_ADDRSTRLEN)))
		inet_ntop(AF_INET, &i, p->Value, INET_ADDRSTRLEN);
}

static inline void returnUnsignedInt(struct soap *soap,
				     struct cwmp__ParameterValueStruct *p,
				     const unsigned int i)
{
	p->__typeValue = SOAP_TYPE_xsd__unsignedInt;
	if ((p->Value = soap_malloc(soap, sizeof(unsigned int))))
		*(unsigned int *)p->Value = i;
}

static inline void returnBoolean(struct soap *soap,
				 struct cwmp__ParameterValueStruct *p,
				 const unsigned int i)
{
	p->__typeValue = SOAP_TYPE_xsd__boolean;
	if ((p->Value = soap_malloc(soap, sizeof(unsigned int))))
		*(unsigned int *)p->Value = i;
}

static inline void returnDateTime(struct soap *soap,
				  struct cwmp__ParameterValueStruct *p,
				  const ticks_t t)
{
	p->__typeValue = SOAP_TYPE_xsd__dateTime;
	if ((p->Value = soap_malloc(soap, sizeof(ticks_t))))
		*(ticks_t *)p->Value = t;
}

#endif
