#ifndef __TR_H_
#define __TR_H_

#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <event.h>

void dm_startup(void);
void dm_shutdown(void);

void *dm_ctrl_thread(void *arg);

#endif
