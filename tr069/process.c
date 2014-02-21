/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2004-2006 Andreas Schultz <aschultz@warp10.net>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <ev.h>

#define SDEBUG
#include "debug.h"
#include "list.h"

#include "process.h"

/*
 * simple client monitoring implementation
 */

struct process_info_t {
	struct process_info_t	*next;
	int			id;

	enum process_state	state;
	struct {
		ev_tstamp	stamp;
		unsigned int	cur;

		unsigned int	max;
		ev_tstamp	span;
	} restart;

	pid_t			pid;
	char			**argv;

	PROCESS_REAPED_CB	cb;
	void			*ud;
};

static struct {
	struct process_info_t	*next;
	int			id;
	pthread_mutex_t		mutex;
} process_info_head = {
	.next		= NULL,
	.id		= 0,
	.mutex		= PTHREAD_MUTEX_INITIALIZER,
};

static pthread_mutex_t reaping_mutex = PTHREAD_MUTEX_INITIALIZER;

static ev_signal evchld;
static ev_async evstart;

#if EV_MULTIPLICITY
static struct ev_loop *process_loop;

#define EV_PROCESS_A	process_loop
#define EV_PROCESS_A_	EV_PROCESS_A,
#else
#define EV_PROCESS_A
#define EV_PROCESS_A_
#endif

static inline int process_id_cmp(struct process_info_t *node, int id)
{
	return INTCMP(node->id, id);
}

static inline int process_pid_cmp(struct process_info_t *node, pid_t pid)
{
	return INTCMP(node->pid, pid);
}

static inline int process_node_cmp(struct process_info_t *n1, struct process_info_t *n2)
{
	return INTCMP(n1->pid, n2->pid);
}

static void process_free_node(struct process_info_t *p)
{
	for (char **av = p->argv; *av != NULL; av++)
		free(*av);
	free(p->argv);
	free(p);
}

static void chld_cb(EV_P_ ev_signal *w, int revents __attribute__((unused)))
{
	debug(": got signal %d\n", w->signum);

	for (;;) {
		struct process_info_t *p;
		int status;
		pid_t pid;

		pthread_mutex_lock(&reaping_mutex);
		pid = waitpid(-1, &status, WNOHANG);
		pthread_mutex_unlock(&reaping_mutex);
		if (pid <= 0)
			break;

		debug(": got SIGCHLD for process %d, status: %x, %x\n", pid, status, __WAIT_INT(status));

		pthread_mutex_lock(&process_info_head.mutex);
		list_search(struct process_info_t, process_info_head, pid, process_pid_cmp, p);
		if (p) {
			switch (p->cb(p, p->state, status, p->ud)) {
			case PROCESS_NOTHING:
				/* fall through */
			case PROCESS_RESTART:
				debug(": trying to restart process %s", p->argv[0]);

				p->restart.cur++;

				if (p->restart.stamp + p->restart.span <= ev_now(EV_A)) {
					p->restart.stamp = ev_now(EV_A);
					p->restart.cur = 0;
				} else if (p->restart.cur >= p->restart.max) {
					logx(LOG_ALERT, "%s: restart limits reached for process %s",
					     __FUNCTION__, p->argv[0]);

					debug(": removing process %s", p->argv[0]);
					list_remove(struct process_info_t, process_info_head, p);
					process_free_node(p);
					break;
				}

				p->pid = daemonize(p->argv);
				debug(": new pid: %d", p->pid);
				if (p->pid > 0) {
					p->state = PROCESS_RUNNING;
					break;
				}

				logx(LOG_ALERT, "%s: restarting process %s failed",
				     __FUNCTION__, p->argv[0]);
				/* fall through */
			case PROCESS_REMOVE:
				debug(": removing process %s", p->argv[0]);
				list_remove(struct process_info_t, process_info_head, p);
				process_free_node(p);
				break;
			}
		}
		pthread_mutex_unlock(&process_info_head.mutex);
	}
}

static void chldasync_cb(EV_P_ ev_async *w __attribute__((unused)),
			 int revents __attribute__((unused)))
{
	struct process_info_t *p, *n;

	debug(": work pending");
	pthread_mutex_lock(&process_info_head.mutex);
	list_foreach_safe(struct process_info_t, process_info_head, p, n) {
		if (p->state == PROCESS_NEW) {
			debug(": trying to start process %s", p->argv[0]);
			p->pid = daemonize(p->argv);
			debug(": new pid: %d", p->pid);
			if (p->pid <= 0) {
				logx(LOG_ALERT, "%s: starting process %s failed",
				     __FUNCTION__, p->argv[0]);
				list_remove(struct process_info_t, process_info_head, p);
				process_free_node(p);
			} else {
				p->state = PROCESS_RUNNING;
				p->restart.stamp = ev_now(EV_A);
			}
		}
	}
	pthread_mutex_unlock(&process_info_head.mutex);
	debug(": work pending - done");
}

void supervisor_init(EV_P)
{
#if EV_MULTIPLICITY
	process_loop = EV_A;
#endif

	ev_signal_init(&evchld, chld_cb, SIGCHLD);
	ev_signal_start(EV_PROCESS_A_ &evchld);

	ev_async_init(&evstart, chldasync_cb);
	ev_async_start(EV_PROCESS_A_ &evstart);
}

void change_process_argv(struct process_info_t *p, const char *const argv[])
{
	const char *const *av;
	char **pav;
	char **new;
	int cArgv = 1;

	ENTER();
	dm_assert(argv != NULL && argv[0] != NULL);

	if (p->argv) {
		for (pav = p->argv; *pav; pav++)
			free(*pav);
	}

	for (av = argv; *av; av++)
		cArgv++;

	new = realloc(p->argv, sizeof(void *) * cArgv);
	if (!new) {
		/* p->argv is still valid */
		free(p->argv);
		p->argv = NULL;

		EXIT();
		return;
	}
	p->argv = new;

	for (av = argv, pav = p->argv; *av; av++, pav++)
		*pav = strdup(*av); /* may fail */
	*pav = NULL;

	EXIT();
}

int supervise_cb(const char *const argv[],
		 unsigned int max_restarts, ev_tstamp restart_timespan,
		 PROCESS_REAPED_CB cb, void *ud)
{
	struct process_info_t *p;
	int id;

	ENTER();
	dm_assert(cb != NULL);

	p = malloc(sizeof(struct process_info_t));
	if (!p) {
		EXIT();
		return 0;
	}
	memset(p, 0, sizeof(struct process_info_t));

	p->state = PROCESS_NEW;
	p->restart.max = max_restarts;
	p->restart.span = restart_timespan;

	change_process_argv(p, argv);

	p->cb = cb;
	p->ud = ud;

	pthread_mutex_lock(&process_info_head.mutex);

	id = p->id = ++process_info_head.id;
	list_append(struct process_info_t, process_info_head, p);
	ev_async_send(EV_PROCESS_A_ &evstart);

	pthread_mutex_unlock(&process_info_head.mutex);

	EXIT();
	return id;
}

enum process_action
default_reaped_cb(struct process_info_t *p __attribute__((unused)),
		  enum process_state state,
		  int status __attribute__((unused)),
		  void *ud __attribute__((unused)))
{
	switch (state) {
	case PROCESS_RUNNING:
		/* undesired crash */
		return PROCESS_RESTART;
	case PROCESS_DYING:
		/* desired termination */
		return PROCESS_REMOVE;
	default:
		break;
	}

	/* shouldn't be reached */
	return PROCESS_NOTHING;
}

int supervise(const char *const argv[])
{
	return supervise_cb(argv, PROCESS_DEFAULT_MAX_RESTARTS,
			    PROCESS_DEFAULT_RESTART_TIMESPAN,
			    PROCESS_DEFAULT_REAPED_CB, NULL);
}

/**
 * run a program that becomes a daemon by itself
 */
int start_daemon(const char *const argv[])
		__attribute__((alias("invoke_executable")));

int invoke_executable(const char *const argv[])
{
	pid_t pid;
	int status = -1;

	pthread_mutex_lock(&reaping_mutex);

	switch (pid = fork()) {
	case -1:	/* error */
		debug("(): fork: %s", strerror(errno));
		break;

	case 0: {	/* child */
		const struct rlimit rlim = {
			.rlim_cur = 0,
			.rlim_max = RLIM_INFINITY
		};
		sigset_t set;
		int _errno;

#if 0
		/* Reset signal handlers set for parent process */
		for (int sig = 0; sig < (_NSIG-1); sig++)
			signal(sig, SIG_DFL);
#endif

		/* Clean up */
		ioctl(0, TIOCNOTTY, 0);
		for (int i = 3; i < 256; i++)
			close(i);

		sigemptyset(&set);
		sigprocmask(SIG_SETMASK, &set, NULL);

		/* disable cores for childs */
		setrlimit(RLIMIT_CORE, &rlim);

		setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin", 1);
		execv(argv[0], argv);
		_errno = errno;
		perror(argv[0]);
		exit(_errno);
	}

	default: {	 /* parent */
#ifdef SDEBUG
		char buf[254] = "";

		for (const char *const *p = argv; *p; p++) {
			size_t l = strlen(buf);
			snprintf(buf + l, sizeof(buf) - l, "%s ", *p);
		}
		debug("(): cmd=[%s]", buf);
#endif

		errno = 0;
		waitpid(pid, &status, 0);
		debug("(): cmd=[%s], rc=%d, error=%s",
		      buf, status, strerror(errno));

		break;
	}
	}

	pthread_mutex_unlock(&reaping_mutex);

	return status;
}

pid_t daemonize(const char *const argv[])
{
	pid_t pid;

	debug("() parent grp: %d\n", getpgrp());

	switch (pid = fork()) {
	case -1:	/* error */
		debug("(): fork: %s", strerror(errno));
		return -1;

	case 0: {	/* child */
		const struct rlimit rlim = {
			.rlim_cur = 0,
			.rlim_max = RLIM_INFINITY
		};
		sigset_t set;
		int _errno;

#if 0
		/* Reset signal handlers set for parent process */
		for (int sig = 0; sig < (_NSIG-1); sig++)
			signal(sig, SIG_DFL);
#endif

		/* Clean up */
		ioctl(0, TIOCNOTTY, 0);
		for (int i = 3; i < 256; i++)
			close(i);
		setsid();

		sigemptyset(&set);
		sigprocmask(SIG_SETMASK, &set, NULL);

		/* disable cores for childs */
		setrlimit(RLIMIT_CORE, &rlim);

		setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin", 1);
		execv(argv[0], argv);
		_errno = errno;
		perror(argv[0]);
		exit(_errno);
	}

	default: {	 /* parent */
#ifdef SDEBUG
		char buf[254] = "";

		for (const char *const *p = argv; *p; p++) {
			size_t l = strlen(buf);
			snprintf(buf + l, sizeof(buf) - l, "%s ", *p);
		}
		debug("(): cmd=[%s]", buf);
#endif

		break;
	}
	}

	return pid;
}


void kill_daemon(pid_t pid, int signal)
{
	debug("(): killing: %d", pid);
	kill(pid, signal);
}

void kill_supervise(int id, int signal)
{
	pid_t pid = 0;
	struct process_info_t *p;

	ENTER();
	pthread_mutex_lock(&process_info_head.mutex);
	list_search(struct process_info_t, process_info_head, id, process_id_cmp, p);
	if (p) {
		pid = p->pid;
		p->state = PROCESS_DYING;
	}
	pthread_mutex_unlock(&process_info_head.mutex);
	if (pid)
		kill_daemon(pid, signal);
	EXIT();
}

void signal_supervise(int id, int signal)
{
	pid_t pid = 0;
	struct process_info_t *p;

	ENTER();
	pthread_mutex_lock(&process_info_head.mutex);
	list_search(struct process_info_t, process_info_head, id, process_id_cmp, p);
	if (p)
		pid = p->pid;
	pthread_mutex_unlock(&process_info_head.mutex);
	if (pid)
		kill_daemon(pid, signal);
	EXIT();
}

pid_t parsepidfile(const char *fname)
{
	FILE *fpid;
	pid_t pid = 0;

	fpid = fopen(fname, "r");
	if (fpid) {
		if (fscanf(fpid, "%d", &pid) != 1)
			pid = 0;
		fclose(fpid);
	}
	return pid;
}

void signalpidfile(const char *fname, int signal)
{
	FILE *fpid;
	pid_t pid;

	fpid = fopen(fname, "r");
	if (fpid) {
		if (fscanf(fpid, "%d", &pid) == 1)
			kill_daemon(pid, signal);
		fclose(fpid);
	}
}

void killpidfile(const char *fname)
{
	signalpidfile(fname, SIGTERM);
}

void sys_echo(const char *file, const char *fmt, ...)
{
	FILE *fout;
	va_list vlist;

	fout = fopen(file, "a+");
	if (!fout)
		return;

	va_start(vlist, fmt);
	vfprintf(fout, fmt, vlist);
	va_end(vlist);

	fclose(fout);
}

int sys_scan(const char *file, const char *fmt, ...)
{
	FILE *fin;
	int rc, _errno;
	va_list vlist;

	fin = fopen(file, "r");
	if (!fin) {
		errno = 0;
		return EOF;
	}

	va_start(vlist, fmt);
	errno = 0;
	rc = vfscanf(fin, fmt, vlist);
	_errno = errno;
	va_end(vlist);

	fclose(fin);

	errno = _errno;
	return rc;
}

int vsystem(const char *cmd)
{
	int rc = 0;
	int _errno;

	debug("(): cmd=[%s]\n", cmd);

	pthread_mutex_lock(&reaping_mutex);
	errno = 0;
	rc = system(cmd);
	_errno = errno;
	pthread_mutex_unlock(&reaping_mutex);

	debug("(): cmd=[%s], rc=%d, error=%s", cmd, rc, strerror(_errno));
	return rc;
}

int vasystem(const char *fmt, ...)
{
	va_list args;
	char	buf[1024];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	return vsystem(buf);
}

int insmod(const char *module)
{
	return va_invoke_executable("/sbin/insmod", module);
}

