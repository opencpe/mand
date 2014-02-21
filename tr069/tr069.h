#ifndef __TR_H_
#define __TR_H_

#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <event.h>

struct soap;

struct soapResult_t {
	int  code;
	char *msg;
};

extern int mngt_srv_url_change;
extern time_t igd_parameters_tstamp
;
extern pthread_t cpe_needs_reboot;
extern pthread_mutex_t cwmp_mutex;

void cwmp_prepare_inform(void);
void cwmp_start_inform(void);
void doBootstrap(void);
char *doKick(char *command, char *referer, char *arg, char *next);

void soap_log_fault(struct soap *soap, const char *func);

void free_inform_soap(struct soap *soap);
struct soap* get_inform_soap(void);
void release_inform_soap(void);

void tr069_startup(void);
void tr069_shutdown(void);

int tr069_boot_notify(void);

void *tr069_ctrl_thread(void *arg);

void tr069_reboot_actions(void);
void tr069_save_events(void);
void tr069_load_events(void);
void tr069_save_requests(void);
void tr069_load_requests(void);

#endif
