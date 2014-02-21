#ifndef _TR_PROCESS_H
#define _TR_PROCESS_H

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <ev.h>

struct process_info_t;

enum process_action {
	PROCESS_NOTHING = 0,
	PROCESS_RESTART,
	PROCESS_REMOVE
};

enum process_state {
	PROCESS_NEW = 0,
	PROCESS_RUNNING,
	PROCESS_DYING
};

typedef enum process_action
	(*PROCESS_REAPED_CB)(struct process_info_t *, enum process_state, int, void *);

#define PROCESS_DEFAULT_MAX_RESTARTS		5	/* 5 restarts */
#define PROCESS_DEFAULT_RESTART_TIMESPAN	10.	/* in 10 seconds */

enum process_action default_reaped_cb(struct process_info_t *, enum process_state, int, void *);
#define PROCESS_DEFAULT_REAPED_CB default_reaped_cb

void supervisor_init(EV_P);

int invoke_executable(const char *const argv[]);
#define va_invoke_executable(PROG, ...) \
	invoke_executable((const char *[]){PROG, ##__VA_ARGS__, NULL})

int start_daemon(const char *const argv[]);
pid_t daemonize(const char *const argv[]);

int supervise_cb(const char *const argv[],
		 unsigned int max_restarts, ev_tstamp restart_timespan,
		 PROCESS_REAPED_CB cb, void *ud);
int supervise(const char *const argv[]);
void change_process_argv(struct process_info_t *p, const char *const argv[]);

void kill_supervise(int pid, int signal);
void signal_supervise(int id, int signal);

pid_t parsepidfile(const char *fname);
void signalpidfile(const char *fname, int signal);
void killpidfile(const char *fname);
void kill_daemon(pid_t pid, int signal);

void sys_echo(const char *file, const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));
int sys_scan(const char *file, const char *fmt, ...)
	__attribute__ ((__format__ (__scanf__, 2, 3)));

int vsystem(const char *cmd);
int vasystem(const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 1, 2)));

int insmod(const char *module);

#endif
