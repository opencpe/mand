/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2004-2006 Andreas Schultz <aschultz@warp10.net>
 * (c) 2007 Travelping GmbH <info@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#include <sys/reboot.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stdarg.h>
#include <syslog.h>

#include <event.h>

#include <features.h>
#if 0
#ifdef __UCLIBC__
#include <bits/atomicity.h>
#endif     /* __UCLIBC__ */
#endif

#include "tr069.h"
#include "soapH.h"
#include "tr.nsmap"

#define SDEBUG
#include "debug.h"

#include "tr069_token.h"
#include "tr069_store.h"
#include "tr069_serialize.h"
#include "tr069_deserialize.h"
#include "tr069_strings.h"
#include "tr069_notify.h"

#include "ifup.h"
#include "tr069_event_queue.h"
#include "tr069_request_queue.h"

#define CRLF "\r\n"

#define ERR_DNS_FAILURE       9801

#define DEBUG 1

#define CACERT "/etc/ssl/dmcacert.crt"

#define CPECERT "/etc/ssl/cpe.crt"
#define CPEKEY  "/etc/ssl/cpe.key"

#define CWMP_SOAP_ACTION "urn:dslforum-org:cwmp-1-0"

void tr069_dump(int fd, const char *element);

		/* in reboot.c */
int sys_shutdown_system(unsigned long magic);

static int retry_count = 0;
static const char *ACS_URL;

pthread_t cpe_needs_reboot = 0;

char *kick_next_url = NULL;

static xsd__string implMethodList[] = { "GetRPCMethods",
					"SetParameterValues",
					"GetParameterValues",
					"GetParameterNames",
					"SetParameterAttribute",
					"GetParameterAttribute",
					"AddObject",
					"DeleteObject",
					"Reboot",
					"Download",
};

int cwmp__GetRPCMethods(struct soap            *soap __attribute__ ((unused)),
			struct MethodListArray *MethodList)
{
	MethodList->__ptrstring = implMethodList;
	MethodList->__size = sizeof(implMethodList) / sizeof(xsd__string *);

	return SOAP_OK;
}

int cwmp__AddObject(struct soap                    *soap __attribute__ ((unused)),
		    xsd__string                    ObjectName,
		    xsd__string                    ParameterKey __attribute__ ((unused)),
		    struct cwmp__AddObjectResponse *result __attribute__ ((unused)))
{
	tr069_selector sb;
	tr069_id id = 0;

	if (!tr069_name2sel(ObjectName, &sb)) {
		cwmp_fault(soap, 9003, "Invalid arguments");
		return SOAP_FAULT;
	}

	if (tr069_add_instance_by_selector(sb, &id)) {
		result->InstanceNumber = id;
		result->Status = 1;
		return SOAP_OK;
	}
	return SOAP_ERR;
}

int cwmp__DeleteObject(struct soap *soap,
		       xsd__string ObjectName,
		       xsd__string ParameterKey __attribute__ ((unused)),
		       xsd__int    *Status)
{
	tr069_selector sb;
	int len;

	len = strlen(ObjectName);
	if (ObjectName[len - 1] != '.') {
		cwmp_fault(soap, 9005, "Invalid Parameter Name");
		return SOAP_FAULT;
	}
	ObjectName[len - 1] = '\0';

	if (!tr069_name2sel(ObjectName, &sb)) {
		cwmp_fault(soap, 9005, "Invalid Parameter Name");
		return SOAP_FAULT;
	}

	if (tr069_del_object_by_selector(sb)) {
		*Status = 0;
		return SOAP_OK;
	}

	cwmp_fault(soap, 9005, "Invalid Parameter Name");
	return SOAP_FAULT;
}


int cwmp__Reboot(struct soap                 *soap __attribute__ ((unused)),
		 xsd__string                 CommandKey,
		 struct cwmp__RebootResponse *result __attribute__ ((unused)))
{
	tr069_add_event(EV_CPE_REBOOT, CommandKey);
	cpe_needs_reboot = pthread_self();
	return SOAP_OK;
}

int cwmp__Inform(struct soap                      *soap __attribute__ ((unused)),
		 struct cwmp__DeviceIdStruct      DeviceId __attribute__ ((unused)),
		 struct EventStructArray          Event __attribute__ ((unused)),
		 xsd__unsignedInt                 MaxEnvelopes __attribute__ ((unused)),
		 xsd__dateTime                    CurrentTime __attribute__ ((unused)),
		 xsd__unsignedInt                 RetryCount __attribute__ ((unused)),
		 struct ParameterValueStructArray ParameterList __attribute__ ((unused)),
		 xsd__unsignedInt                 *retMaxEnvelopes __attribute__ ((unused)))
{
	return SOAP_FAULT;
}

int cwmp__ScheduleInform(struct soap                         *soap __attribute__ ((unused)),
			 xsd__unsignedInt                    DelaySeconds __attribute__ ((unused)),
			 xsd__string                         CommandKey __attribute__ ((unused)),
			 struct cwmp__ScheduleInformResponse *result __attribute__ ((unused)))
{
	return SOAP_ERR;
}

int cwmp__Kicked(struct soap *soap __attribute__ ((unused)),
		 xsd__string Command __attribute__ ((unused)),
		 xsd__string Referer __attribute__ ((unused)),
		 xsd__string Arg __attribute__ ((unused)),
		 xsd__string Next __attribute__ ((unused)),
		 xsd__string *NextURL __attribute__ ((unused)))
{
	return SOAP_ERR;
}

static inline void *soap_safe_malloc(struct soap *soap, size_t size)
{
	void *ptr = soap_malloc(soap, size);
	if (ptr)
		memset(ptr, 0, size);
	return ptr;
}

static inline void free_soap_result(struct soapResult_t *result)
{
	free(result->msg);
}

void inform_add_parameter_str(struct soap *soap,
			      struct ParameterValueStructArray *inform_parameter_values,
			      char *name, char *value)
{
	if (!inform_parameter_values->__ptrParameterValueStruct)
		inform_parameter_values->__ptrParameterValueStruct = soap_safe_malloc(soap, 64 * sizeof(struct cwmp__ParameterValueStruct));
	if (inform_parameter_values->__size < 64) {
		inform_parameter_values->__ptrParameterValueStruct[inform_parameter_values->__size].Name  = name;
		inform_parameter_values->__ptrParameterValueStruct[inform_parameter_values->__size].__typeValue = SOAP_TYPE_xsd__string;
		inform_parameter_values->__ptrParameterValueStruct[inform_parameter_values->__size].Value = value;
		inform_parameter_values->__size++;
	}
}

#ifdef DEBUG

void soap_log_fault(struct soap *soap, const char *func)
{
	char *s = NULL;

	soap_asprint_fault(soap, &s);

	if (s) {
		logx(LOG_NOTICE, "%s: %s", func, s);
		free(s);
	}
}

#else

void soap_log_fault(struct soap *soap __attribute__((unused)),
		    const char *func __attribute__((unused)))
{
}

#endif

static void
eval_soap_fault(struct soap *soap, struct soapResult_t *soapResult)
{
	if (soap->fault &&
	    soap->fault->detail &&
	    soap->fault->detail->__type == SOAP_TYPE__cwmp__Fault) {
		struct _cwmp__Fault *fault = (struct _cwmp__Fault *)soap->fault->detail->fault;

		soapResult->code = fault->FaultCode;
		soapResult->msg  = fault->FaultString ? strdup(fault->FaultString) : NULL;
	}
}

int inform_exec(struct soap *soap,
		struct EventStructArray *inform_event,
		struct ParameterValueStructArray *inform_parameter_values)
{
	int status, ret;
	struct tr069_value_table *dit;
	struct cwmp__DeviceIdStruct device_id;

	ENTER();

	memset(&device_id, 0, sizeof(device_id));
	/** VAR: InternetGatewayDevice.DeviceInfo */
	dit = tr069_get_table_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							    cwmp__IGD_DeviceInfo, 0 });

	if (dit) {
		/** VAR: InternetGatewayDevice.DeviceInfo.Manufacturer */
		device_id.Manufacturer = tr069_get_string_by_id(dit, cwmp__IGD_DevInf_Manufacturer);
		/** VAR: InternetGatewayDevice.DeviceInfo.ManufacturerOUI */
		device_id.OUI = tr069_get_string_by_id(dit, cwmp__IGD_DevInf_ManufacturerOUI);
		/** VAR: InternetGatewayDevice.DeviceInfo.SerialNumber */
		device_id.SerialNumber = tr069_get_string_by_id(dit, cwmp__IGD_DevInf_SerialNumber);
		/** VAR: InternetGatewayDevice.DeviceInfo.ProductClass */
		device_id.ProductClass = tr069_get_string_by_id(dit, cwmp__IGD_DevInf_ProductClass);
	}

	if ((ret = soap_call_cwmp__Inform(soap,
					  ACS_URL,
					  CWMP_SOAP_ACTION,
					  device_id,
					  *inform_event,
					  1,
					  time2ticks(time(NULL)),
					  retry_count,
					  *inform_parameter_values,
					  &status)) != SOAP_OK) {
		soap_log_fault(soap, __FUNCTION__);
		retry_count++;
	} else {
		retry_count = 0;
	}

	EXIT();
	return ret;
}

int (*soap_fpost)(struct soap*, const char*, const char*, int, const char*, const char*, size_t);
int (*soap_fresponse)(struct soap*, int, size_t);

static char *ACS_HOST;
static int  ACS_PORT;
static char *ACS_PATH;

int http_rev_response(struct soap *soap,
		      int status __attribute__ ((unused)),
		      size_t count)
{
	return soap_fpost(soap, ACS_URL, ACS_HOST, ACS_PORT, ACS_PATH, NULL, count);
}

int http_rev_post(struct soap *soap,
		  const char *endpoint __attribute__ ((unused)),
		  const char *host __attribute__ ((unused)),
		  int port __attribute__ ((unused)),
		  const char *path __attribute__ ((unused)),
		  const char *action __attribute__ ((unused)),
		  size_t count)
{
	return soap_fresponse(soap, 200, count);
}

void http_update_endpoint(void)
{
	static char *endpoint = NULL;
	char *port;

	/** VAR: InternetGatewayDevice.ManagementServer.URL */
	ACS_URL = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
								 cwmp__IGD_ManagementServer,
								 cwmp__IGD_MgtSrv_URL, 0 });

	if (ACS_URL) {
		free(endpoint);
		endpoint = strdup(ACS_URL);

		ACS_PORT = 80;
		ACS_HOST = endpoint + 7;
		if (!strncasecmp(endpoint, "https:", 5)) {
			ACS_HOST++;
			ACS_PORT = 443;
		}
		if ((ACS_PATH = strchr(ACS_HOST, '/')))
			*ACS_PATH++ = '\0';
		if ((port = strchr(ACS_HOST, ':'))) {
			*port++ = '\0';
			ACS_PORT = atoi(port);
		}

		printf("ACS_HOST: %s, ACS_PORT: %d, ACS_PATH: %s\n", ACS_HOST, ACS_PORT, ACS_PATH);
	}
}

void http_reverse_connection(struct soap *soap)
{
	soap_fpost      = soap->fpost;
	soap->fpost     = http_rev_post;
	soap_fresponse  = soap->fresponse;
	soap->fresponse = http_rev_response;
}

static inline void reset_inform(struct EventStructArray *inform_event,
				struct ParameterValueStructArray *inform_parameter_values)
{
	memset(inform_event, 0, sizeof(struct EventStructArray));
	memset(inform_parameter_values, 0, sizeof(struct ParameterValueStructArray));
}

int tr069_soap_init2(struct soap *soap)
{
	soap_init2(soap,
		   SOAP_IO_DEFAULT | SOAP_IO_KEEPALIVE,
		   SOAP_IO_DEFAULT | SOAP_IO_KEEPALIVE | SOAP_XML_NIL | SOAP_IO_LENGTH );

#if defined(SOAP_DEBUG)
	soap_set_recv_logfile(soap, "/var/log/soap_recv.log");
	soap_set_sent_logfile(soap, "/var/log/soap_sent.log");
	soap_set_test_logfile(soap, "/var/log/soap_test.log");
#endif

	soap->connect_timeout = 30;
	soap->recv_timeout = 30;
	soap->send_timeout = 30;

#if defined(WITH_OPENSSL) || defined(WITH_AXTLS) || defined(WITH_POLARSSL)
	if (soap_ssl_client_context(soap,
				    SOAP_SSL_REQUIRE_SERVER_AUTHENTICATION | SOAP_SSL_RSA | SOAP_TLSv1,     /* SOAP_SSL_DEFAULT, */
				    CPECERT,
				    CPEKEY,
				    NULL,               /* password to read the key file */
				    CACERT,             /* optional cacert file to store trusted certificates */
				    NULL,               /* optional capath to directory with trusted certificates */
				    NULL) != SOAP_OK) {
		soap_log_fault(soap, __FUNCTION__);
		return SOAP_ERR;
	}
#endif
	return SOAP_OK;
}

static int start_inform(struct soap *soap,
			struct EventStructArray *inform_event,
			struct ParameterValueStructArray *inform_parameter_values)
{
	const char *tmp;
	char *user;
	int i;

	ENTER();

	/** VAR: InternetGatewayDevice.ManagementServer.Username */
	tmp = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							     cwmp__IGD_ManagementServer,
							     cwmp__IGD_MgtSrv_Username, 0 });
	if (tmp) {
		user = (char *)soap_malloc(soap, 128);
		i = 0;
		while (*tmp && i < (128-4)) {
			if (*tmp != ':')
				user[i++] = *tmp;
			else
				i += sprintf(&user[i], "%%%02X", *tmp);
			tmp++;
		}
		user[i] = '\0';
		soap->userid = user;
	}
	/** VAR: InternetGatewayDevice.ManagementServer.Password */
	soap->passwd = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
							     cwmp__IGD_ManagementServer,
							     cwmp__IGD_MgtSrv_Password, 0 });

	EXIT();
	return inform_exec(soap, inform_event, inform_parameter_values);
}

static int dm_soap_serve(struct soap *soap)
{
	int r = SOAP_OK;
	unsigned int k = soap->max_keep_alive;

	ENTER();

        do {
                soap_begin(soap);

                if (soap->max_keep_alive > 0 && !--k)
                        soap->keep_alive = 0;

                if (soap_begin_recv(soap)) {
			if (soap->error < SOAP_STOP) {
				if (soap->error == SOAP_NO_DATA) {
					soap_closesock(soap);
					r = SOAP_OK;
					EXIT();
					break;
				} else {
					r = soap_send_fault(soap);
					EXIT();
					break;
				}
			}

                        soap_closesock(soap);
                        continue;
                }

                if (soap_envelope_begin_in(soap)
		    || soap_recv_header(soap)
		    || soap_body_begin_in(soap)) {
                        r = soap_send_fault(soap);
			EXIT();
			break;
                }
		if (soap_serve_request(soap)
		    || (soap->fserveloop && soap->fserveloop(soap))) {
			r = soap_send_fault(soap);
			EXIT();
			break;
		}
        } while (soap->keep_alive);

	EXIT();

        return r;
}

pthread_mutex_t cwmp_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cwmp_cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t cwmp_kick_cond = PTHREAD_COND_INITIALIZER;
static int cwmp_inform_pending = 0;

static void do_inform(struct soap *soap,
		      struct EventStructArray *inform_event,
		      struct ParameterValueStructArray *inform_parameter_values,
		      int *deliveredBS, struct soapResult_t *soapResult)
{
	int r;
	char buf[1024];
	int errnum;
	struct hostent hostent, *host;

	ENTER();

	http_update_endpoint();

	if (!ACS_HOST ||
	    gethostbyname_r(ACS_HOST, &hostent, buf, sizeof(buf), &host, &errnum)) {
		soapResult->code = ERR_DNS_FAILURE;
		EXIT();
		return;
	}

	if (start_inform(soap, inform_event, inform_parameter_values) != SOAP_OK) {
		eval_soap_fault(soap, soapResult);
		EXIT();
		return;
	}

	*deliveredBS = tr069_have_event(EV_CPE_BOOTSTRAP);
	tr069_clear_inform_events();

	r = tr069_dispatch_queued_requests(soap, ACS_URL, CWMP_SOAP_ACTION);
	/* NOTE: fault is only evaluated if there is no keep alive */

	http_reverse_connection(soap);

	soap->version = 0;
	if (soap_connect(soap, ACS_URL, CWMP_SOAP_ACTION) != SOAP_OK ||
	    soap_send_empty_response(soap, SOAP_OK) != SOAP_OK) {
		soapResult->code = 9002 /* Internal error */;
		EXIT();
		return;
	}
	soap->version = 1;

	r = dm_soap_serve(soap);
	if (r == SOAP_OK || (r == SOAP_VERSIONMISMATCH && !soap->keep_alive))
		soapResult->code = 0;
	else
		eval_soap_fault(soap, soapResult);

	EXIT();
	return;
}

void cwmp_prepare_inform(void)
{
	cwmp_inform_pending = 1;
	pthread_cond_signal(&cwmp_cond);
}

void cwmp_start_inform(void)
{
	pthread_mutex_lock(&cwmp_mutex);
	cwmp_prepare_inform();
	pthread_mutex_unlock(&cwmp_mutex);
}

void doBootstrap()
{
	tr069_add_event(EV_CPE_BOOTSTRAP, NULL);
	cwmp_start_inform();
}

int cwmp_kick(char *command, char *referer, char *arg, char *next, int timeout)
{
	int r = 0;
	struct timespec ts;

	pthread_mutex_lock(&cwmp_mutex);

	if (tr069_add_kicked_request(command, referer, arg, next)) {
		pthread_mutex_unlock(&cwmp_mutex);
		return -1;
	}
	tr069_add_event(EV_CPE_KICKED, NULL);

	free(kick_next_url);
	kick_next_url = NULL;

	cwmp_inform_pending = 1;
	pthread_cond_signal(&cwmp_cond);

	clock_gettime(CLOCK_REALTIME, &ts);
	ts.tv_sec += timeout;

	r = pthread_cond_timedwait(&cwmp_kick_cond, &cwmp_mutex, &ts) ||
	    !kick_next_url;

	pthread_mutex_unlock(&cwmp_mutex);

	return r;
}

int tr069_boot_notify(void)
{
	tr069_add_event(EV_CPE_BOOT, NULL);
	cwmp_start_inform();

	return 0;
}

static void cwmp_check_next_inform(struct timespec *next)
{
	static unsigned int interval = 0;
	static time_t base_time = 0;
	static time_t igd_tstamp = -1;
	static char pi_enabled = 0;
	static time_t next_time = 0;

	time_t current_time = time(NULL);

	ENTER();

	if (igd_tstamp != igd_parameters_tstamp) {
		struct tr069_value_table *mss;

		mss = tr069_get_table_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
								    cwmp__IGD_ManagementServer, 0});
		if (!mss) {
			pi_enabled = 0;
			interval = 0;
			base_time = 0;
		} else {
			/** VAR: InternetGatewayDevice.ManagementServer.PeriodicInformEnable */
			pi_enabled = tr069_get_bool_by_id(mss, cwmp__IGD_MgtSrv_PeriodicInformEnable);

			/** VAR: InternetGatewayDevice.ManagementServer.PeriodicInformInterval */
			interval = tr069_get_uint_by_id(mss, cwmp__IGD_MgtSrv_PeriodicInformInterval);

			/** VAR: InternetGatewayDevice.ManagementServer.PeriodicInformTime */
			base_time = tr069_get_time_by_id(mss, cwmp__IGD_MgtSrv_PeriodicInformTime);
		}

		debug("() PI enabled: %d\n", pi_enabled);
		debug("() Interval: %d\n", interval);
		debug("() Base: %d\n", base_time);

		next_time = 0;
		igd_tstamp = igd_parameters_tstamp;
	}

	if (interval <= 0)
		interval = 60;

	if (base_time <= 0) {
		base_time = current_time;
		next_time = current_time + interval;
	}
	else if (base_time > current_time)
		next_time = base_time;

	if (next_time != 0 && next_time <= current_time) {
		if (pi_enabled) {
			tr069_add_event(EV_CPE_PERIODIC, NULL);
			cwmp_inform_pending = 1;
		}

		if (retry_count) {
			float wait;

			if (retry_count < 10)
				wait = (1 << (retry_count - 1)) * 5.0;
			else
				wait = 2560;

			wait += wait * (rand() / (RAND_MAX + 1.0));
			next_time = current_time + wait;

			debug("(): retry: %d, wait: %f, next: %d", retry_count, wait, next_time);
		} else if (next_time == current_time)
			next_time += interval;
		else
			next_time = 0;
	}

	if (next_time == 0) {
		ldiv_t D;

		D = ldiv(current_time - base_time, interval);
		if (D.rem == 0)
			D.quot++;
		next_time = base_time + (D.quot + 1) * interval;
	}

	if (next) {
		next->tv_sec = next_time;
		next->tv_nsec = 0;
	}

	EXIT();
}

/** handle all cwmp activities */
static void *tr069_cwmp_thread(void *arg __attribute__ ((unused)))
{
	pthread_mutex_lock(&cwmp_mutex);

	while (42) {
		struct timespec next;

		cwmp_check_next_inform(&next);
		if (!cwmp_inform_pending)
			pthread_cond_timedwait(&cwmp_cond, &cwmp_mutex, &next);

		if (cwmp_inform_pending) {
			struct soapResult_t ret = {9002 /* Internal error */, NULL};
			int deliveredBS = 0;

			struct soap soap;
			struct EventStructArray inform_event;
			struct ParameterValueStructArray inform_parameter_values;

			memset(&soap, 0, sizeof(soap));
			reset_inform(&inform_event, &inform_parameter_values);

			if (tr069_soap_init2(&soap) == SOAP_OK) {
				char *tmp;

				ENTER();

				/** VAR: InternetGatewayDevice.DeviceInfo.ProvisioningCode */
				tmp = tr069_get_string_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
										     cwmp__IGD_DeviceInfo,
										     cwmp__IGD_DevInf_ProvisioningCode, 0 });
				debug("(): prov code: %p", tmp);
				if (tmp)
					inform_add_parameter_str(&soap, &inform_parameter_values,
								 "InternetGatewayDevice.DeviceInfo.ProvisioningCode",
								 tmp);

				tr069_add_events_to_inform(&soap, &inform_event);
				do_inform(&soap, &inform_event, &inform_parameter_values, &deliveredBS, &ret);

				EXIT_MSG(": ret: %d", ret.code);
			}

			soap_destroy(&soap);
			soap_end(&soap);
			soap_done(&soap);

			/* there was a BOOTSTRAP event and it could be delivered successfully */
			if (deliveredBS) {
				/** VAR: InternetGatewayDevice.ManagementServer.X_TPOSS_Bootstrap */
				struct tr069_value_table *mst = tr069_get_table_by_selector((tr069_selector) {
					cwmp__InternetGatewayDevice,
					cwmp__IGD_ManagementServer,
					cwmp__IGD_MgtSrv_X_TPOSS_Bootstrap, 0
				});

				/** VAR: InternetGatewayDevice.ManagementServer.X_TPOSS_Bootstrap.Status */
				tr069_set_uint_by_id(mst, cwmp__IGD_MgtSrv_X_TPBS_Status, ret.code);
				/** VAR: InternetGatewayDevice.ManagementServer.X_TPOSS_Bootstrap.Message */
				tr069_set_string_by_id(mst, cwmp__IGD_MgtSrv_X_TPBS_Message, ret.msg);
				/** VAR: InternetGatewayDevice.ManagementServer.X_TPOSS_Bootstrap.BootstrapState */
				tr069_set_enum_by_id(mst, cwmp__IGD_MgtSrv_X_TPBS_BootstrapState,
						     cwmp___IGD_MgtSrv_X_TPBS_BootstrapState_Complete);
			}

			exec_pending_notifications();

			cwmp_inform_pending = 0;

			if (cpe_needs_reboot == pthread_self()) {
				tr069_save();
				tr069_reboot_actions();
				sys_shutdown_system(RB_AUTOBOOT);
			}

			free_soap_result(&ret);
		}
	}

	pthread_mutex_unlock(&cwmp_mutex);

	return NULL;
}

/* Strip trailing CR/NL from string <s> */
#define chomp(s) ({ \
        char *c = (s) + strlen((s)) - 1; \
        while ((c > (s)) && (*c == '\n' || *c == '\r' || *c == ' ')) \
                *c-- = '\0'; \
        s; \
})

#ifdef WITH_OPENSSL
int CRYPTO_thread_setup(void);
void CRYPTO_thread_cleanup(void);
#endif

void tr069_startup(void)
{
	pthread_t tid;
	struct timeval tv;

#if defined(WITH_OPENSSL) || defined(WITH_AXTLS)
	soap_ssl_init();
#endif
#ifdef WITH_OPENSSL
	if (CRYPTO_thread_setup()) {
		fprintf(stderr, "Cannot setup crypto thread mutex\n" );
	}
#endif

	pthread_create(&tid, NULL, tr069_cwmp_thread, NULL);
	tr069_boot_notify();
}

void tr069_shutdown()
{
#ifdef WITH_OPENSSL
	CRYPTO_thread_cleanup();
#endif
}
