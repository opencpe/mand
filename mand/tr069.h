#ifndef __TR_H_
#define __TR_H_

#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <event.h>

void tr069_startup(void);
void tr069_shutdown(void);

void *tr069_ctrl_thread(void *arg);

#endif
