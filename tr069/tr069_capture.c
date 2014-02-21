/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) Travelping GmbH <info@travelping.com>
 *
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <pcap.h>
#include <sys/time.h>

#include "tr069_capture.h"

#define SDEBUG
#include "debug.h"

#define CAPFILE		"/tmp/dump.cap"
#define EPKGSZ		1500
#define POLLINT		2000

static pcap_t *handle;
static pcap_dumper_t *dump;
static char *perrbuf;
static const char *cause = "Capture stopped because of ";
static int cptrdbts, cptrdpkgs, mxcfsz, mxpkgs, cap_fd;
static ev_io cap_fd_watcher;
static double tout;
static ev_timer timeout_watcher;

int initcap(const char *interface, unsigned int timeout, unsigned int maxkbytes,
	    unsigned int maxpackages)
{
	cptrdbts  = 0;
	cptrdpkgs = 0;
	tout = (double)timeout / 1024.;
	mxcfsz = maxkbytes * 1024;
	mxpkgs = maxpackages;

	if (!(perrbuf = calloc(PCAP_ERRBUF_SIZE, 1))) {
		debug("(): Couldn't allocate error buffer.\n");
		return -1;
	}
	if (!(handle = pcap_open_live(interface, EPKGSZ, 1, tout, perrbuf))) {
		debug("(): Couldn't get handle to interface %s %s.\n", interface, perrbuf);
		return -1;
	}
	if (pcap_setnonblock(handle, 1, perrbuf) < 0) {
		debug("(): Couldn't set nonblocking IO, %s.\n", perrbuf);
		return -1;
	}
	if ((cap_fd = pcap_get_selectable_fd(handle)) < 0) {
		debug("(): Couldn't get a pollable filedescriptor.\n");
		return -1;
	}
	if (!(dump = pcap_dump_open(handle, CAPFILE))) {
		debug("(): Couldn't open capture file %s %s.\n", interface, pcap_geterr(handle));
		return -1;
	}

	return 0;
}

void cleancap(void)
{
	if (pcap_dump_flush(dump) < 0)
		debug("(): Unable to flush capture file.\n");
	pcap_dump_close(dump);
	pcap_close(handle);
	free(perrbuf);
}

static void got_packet(u_char *args __attribute__((unused)), const struct pcap_pkthdr *header,
		       const u_char *packet)
{
	cptrdbts += header->caplen;
	pcap_dump((u_char*)dump, header, packet);
}

void cap_rem_watchers(EV_P)
{
	ev_io_stop(EV_A_ &cap_fd_watcher);
	ev_timer_stop(EV_A_ &timeout_watcher);
}

static void cap_cb(EV_P_ struct ev_io *w __attribute__((unused)), int revents)
{
	int r;

	r = pcap_dispatch(handle, mxpkgs - cptrdpkgs, got_packet, NULL);
	if(r < 0)
		debug("() Error reading packages %s.\n", pcap_geterr(handle));
	cptrdpkgs += r;

	if (cptrdpkgs >= mxpkgs) {
		debug("() %spackage limit.\n", cause);
		ev_unloop(EV_A_ EVUNLOOP_ONE);
	}
	if (cptrdbts >= mxcfsz) {
		debug("() %scapture file size limit.\n", cause);
		ev_unloop(EV_A_ EVUNLOOP_ONE);
	}
}

static void timeout_cb(EV_P_ struct ev_timer *w __attribute__((unused)),
		       int revents __attribute__((unused)))
{
	debug("() %stimeout.\n", cause);

	ev_unloop(EV_A_ EVUNLOOP_ONE);
}

void cap_start_watchers(EV_P)
{
	ev_io_init(&cap_fd_watcher, cap_cb, cap_fd, EV_READ);
	ev_io_start(EV_A_ &cap_fd_watcher);
	ev_timer_init(&timeout_watcher, timeout_cb, tout, 0.);
	ev_timer_start(EV_A_ &timeout_watcher);
}

