#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <pthread.h>
#include "compiler.h"

#define SDEBUG
#include "debug.h"

#include "tr069.h"
#include "tr069_download.h"
#include "soapH.h"

extern int firmware_upgrade;
extern pthread_mutex_t firmware_upgrade_mutex;

static void _cwmp_fault(struct soap *soap, unsigned int code, char *msg)
{
	static struct _cwmp__Fault fault;

	memset(&fault, 0, sizeof(fault));
	fault.FaultCode = code;
	fault.FaultString = msg;

	soap_receiver_fault(soap, "CWMP fault", NULL);

	soap->fault->detail = (struct SOAP_ENV__Detail*)soap_malloc(soap, sizeof(struct SOAP_ENV__Detail));
	soap->fault->detail->__type = SOAP_TYPE__cwmp__Fault;
	soap->fault->detail->__any = NULL;
	soap->fault->detail->fault = &fault;
}

static char *safe_strdup(const char *s)
{
	if (likely(s && *s))
		return strdup(s);
	return NULL;
}

int cwmp__Download(struct soap                   *soap,
		   xsd__string                   CommandKey,
		   xsd__string                   FileType,
		   xsd__string                   url,
		   xsd__string                   Username,
		   xsd__string                   Password,
		   xsd__unsignedInt              FileSize,
		   xsd__string                   TargetFileName,
		   xsd__unsignedInt              DelaySeconds,
		   xsd__string                   SuccessURL __attribute__ ((unused)),
		   xsd__string                   FailureURL __attribute__ ((unused)),
		   struct cwmp__DownloadResponse *result)
{
	int id;
	char *s;

	ENTER();

	memset(result, 0, sizeof(struct cwmp__DownloadResponse));

	for (s = FileType ; *s != '\0' && !isspace(*s) ; ++s)
		;
	if (*s != '\0')
		*s++ = '\0';

	if (!url || !*url) {
		_cwmp_fault(soap, 9000, "invalid download URL");
		EXIT();
		return SOAP_FAULT;
	}

	switch (id = atoi(FileType)) {
	case 1: {
		pthread_t dl_id;
		struct download_info *dli;

		if (!TargetFileName || !*TargetFileName) {
			_cwmp_fault(soap, 9000, "invalid TargetFileName");
			EXIT();
			return SOAP_FAULT;
		}

		if (firmware_upgrade) {
			_cwmp_fault(soap, 9000, "upgrade already in progress");
			EXIT();
			return SOAP_FAULT;
		}

		pthread_mutex_lock(&firmware_upgrade_mutex);
		if (firmware_upgrade) {
			pthread_mutex_unlock(&firmware_upgrade_mutex);
			_cwmp_fault(soap, 9000, "upgrade already in progress");
			EXIT();
			return SOAP_FAULT;
		}
		firmware_upgrade = 1;
		pthread_mutex_unlock(&firmware_upgrade_mutex);

		dli = malloc(sizeof(struct download_info));
		if (!dli) {
			_cwmp_fault(soap, 9000, "out of memory");
			EXIT();
			return SOAP_FAULT;
		}
		dli->command_key  = safe_strdup(CommandKey);
		dli->file_type_id = id;
		dli->file_type    = safe_strdup(s);
		dli->url          = safe_strdup(url);
		dli->username     = safe_strdup(Username);
		dli->password     = safe_strdup(Password);
		dli->filesize     = FileSize;
		dli->filename     = safe_strdup(TargetFileName);
		dli->delay        = DelaySeconds;

		pthread_create(&dl_id, NULL, thread_firmware_upgrade, dli);
		pthread_detach(dl_id);
		break;
	}
	case 2: {
		pthread_t dl_id;
		struct download_info *dli;

		dli = malloc(sizeof(struct download_info));
		if (!dli) {
			_cwmp_fault(soap, 9000, "out of memory");
			EXIT();
			return SOAP_FAULT;
		}
		dli->command_key  = safe_strdup(CommandKey);
		dli->file_type_id = id;
		dli->file_type    = safe_strdup(s);
		dli->url          = safe_strdup(url);
		dli->username     = safe_strdup(Username);
		dli->password     = safe_strdup(Password);
		dli->filesize     = FileSize;
		dli->filename     = safe_strdup(TargetFileName);
		dli->delay        = DelaySeconds;

		pthread_create(&dl_id, NULL, thread_web_content_download, dli);
		pthread_detach(dl_id);
		break;
	}
	case 3:
	default:
		_cwmp_fault(soap, 9000, "unsupported download");
		EXIT();
		return SOAP_FAULT;
	}

	result->Status = 1;
	EXIT();
	return SOAP_OK;
}

int cwmp__TransferComplete(struct soap                           *soap,
			   xsd__string                           CommandKey   __attribute__ ((unused)),
			   struct cwmp__FaultStruct              FaultStruct  __attribute__ ((unused)),
			   xsd__dateTime                         StartTime    __attribute__ ((unused)),
			   xsd__dateTime                         CompleteTime __attribute__ ((unused)),
			   struct cwmp__TransferCompleteResponse *result      __attribute__ ((unused)))

{
	_cwmp_fault(soap, 9000, "unsupported methode call");
	return SOAP_FAULT;
}

