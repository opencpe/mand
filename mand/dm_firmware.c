#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdarg.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/reboot.h>

#include <httpget.h>

#define SDEBUG
#include "debug.h"
#define LOG_INTERVAL 10 /* log download/fwupdate progress approx. every X percent */

#include "dm.h"
#include "dm_store.h"
#include "dm_download.h"
#include "dm_event_queue.h"
#include "dm_request_queue.h"

#include "mtd.h"
#include "ftools.h"

		/* in reboot.c */
int sys_shutdown_system(unsigned long magic);

extern int firmware_upgrade;
extern pthread_mutex_t firmware_upgrade_mutex;

static int
download_progress(HTTPGET_RC rc __attribute__((unused)),
		  void *user_data __attribute__((unused)),
		  uint32_t downloaded, uint32_t filesize, uint32_t speed)
{
	debug(": %u/%u (%u%%) at %u bytes/s",
	      downloaded, filesize, filesize ? PERCENTAGE(downloaded, filesize) : 0, speed);

	return 0;
}

static void
fw_progress(const char *msg, int state __attribute__((unused)), int total,
	    int current, const char *unit)
{
#ifdef SDEBUG
	static int p;

	if (!current)
		p = 0;

	if (p <= PERCENTAGE(current, total)) {
		debug(": %s: %d%s/%u%s (%u%%)",
		      msg, current, unit, total, unit, PERCENTAGE(current, total));
		p += LOG_INTERVAL;
	}
#endif
}

static void
fw_finish(int code, const char *fmt, ...)
{
#ifdef SDEBUG
	va_list ap;
	char buf[256];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);	/* ignore possible truncation */
	buf[sizeof(buf)-1] = '\0';
	va_end(ap);

	debug(": %s (%d)", buf, code);
#endif
}

static int
httpget_to_cwmp_fault(HTTPGET_RC rc)
{
	switch (rc) {
	case HTTPGET_OK:
		return 0; /* OK */
	case HTTPGET_ERR_UNKNOWN_HOST:
	case HTTPGET_ERR_CONNECTION:
		return 9015; /* Unable to contact file server */
	case HTTPGET_ERR_TIMEOUT:
	case HTTPGET_ERR_READING:
	case HTTPGET_ERR_WRITING:
	case HTTPGET_ERR_FILE:
		return 9017; /* Unable to complete download */
	case HTTPGET_ERR_HTTP:
		return 9016; /* Unable to access file */
	case HTTPGET_ERR_SSL_CACERT:
	case HTTPGET_ERR_SSL_HANDSHAKE:
		return 9012; /* File transfer server authentication failure */
	case HTTPGET_ERR_MISC:
	case HTTPGET_OOM:
	default:
		return 9002; /* Internal error */
	}

	/* never reached */
	return 9002;
}

void *thread_firmware_upgrade(void *arg)
{
	struct download_info *dli = (struct download_info *)arg;
	FILE *output;
	int size;
	HTTPGET_RC http_rc;
	int faultCode = 0; /* OK */
	xsd__dateTime startTime = time2ticks(time(NULL));

	ENTER();
	assert(dli != NULL);

        pthread_mutex_lock(&cwmp_mutex);

	pthread_mutex_lock(&firmware_upgrade_mutex);
	assert(firmware_upgrade == 1);
	pthread_mutex_unlock(&firmware_upgrade_mutex);

	output = tmpfile();
	if (!output) {
		debug(": unable to create tempfile for firmware upgrade");

		faultCode = 9002; /* Internal error */
		goto out;
	}

	debug(": downloading %s...", dli->url);
	http_rc = http_get(dli->url, NULL, output, download_progress, NULL, LOG_INTERVAL);
	if (http_rc) {
		debug(": firmware download failed: rc = %u", http_rc);

		faultCode = httpget_to_cwmp_fault(http_rc);
		goto out_close;
	}
	debug(": doing firmware update");

	fseek(output, 0, SEEK_SET);

	fw_callbacks.fw_progress = fw_progress;
	fw_callbacks.fw_finish = fw_finish;

	if (validate_tpfu(output, &size)) {
		faultCode = 9019; /* File authentication failure */
	} else {
		debug(": writing firmware to flash...");
		if (write_firmware(output, size, dli->filename)) {
			debug(": failed!");
			faultCode = 9018; /* File corrupted */ /* FIXME: maybe inappropriate */
		} else {
			debug(": success!");
		}
	}

 out_close:
	fclose(output);

 out:
 	pthread_mutex_lock(&firmware_upgrade_mutex);
	firmware_upgrade = 0;
	pthread_mutex_unlock(&firmware_upgrade_mutex);

	dm_add_event(EV_CPE_TRANS_COMPL, dli->command_key);
	dm_add_event(EV_CPE_DOWNLOAD, dli->command_key);
	dm_add_transfer_complete_request(
		dli->command_key,
		(struct cwmp__FaultStruct) {faultCode, NULL},
		startTime,
		faultCode == 0 /* OK */ ? 0 : time2ticks(time(NULL)));

	free_download_info(dli);

	if (faultCode == 0 /* OK */) {
		dm_reboot_actions();
		sys_shutdown_system(RB_AUTOBOOT);
		/* not reached: Inform won't be started */
	}

	cwmp_prepare_inform();
	pthread_mutex_unlock(&cwmp_mutex);

	EXIT();
	return NULL;
}

void *thread_web_content_download(void *arg)
{
	struct download_info *dli = (struct download_info *)arg;
	char fname[128];
	FILE *output;
	HTTPGET_RC http_rc;
	int faultCode = 0; /* OK */
	xsd__dateTime startTime = time2ticks(time(NULL));

	ENTER();
	assert(dli != NULL);

        pthread_mutex_lock(&cwmp_mutex);

	snprintf(fname, sizeof(fname), "%s.%d", dli->filename, pthread_self());
	output = fopen(fname, "wb+");
	if (!output) {
		debug(": unable to create tempfile for web content update");

		faultCode = 9002; /* Internal error */
		goto out;
	}

	debug(": downloading %s...", dli->url);
	http_rc = http_get(dli->url, NULL, output, download_progress, NULL, LOG_INTERVAL);
	if (http_rc) {
		debug(": web content download failed: rc = %u", http_rc);
		fclose(output);

		faultCode = httpget_to_cwmp_fault(http_rc);
		goto out;
	}
	fclose(output);

	debug(": doing web content update");

	debug(": updating...");
	if (rename(fname, dli->filename) != 0) {
		debug(": failed!");
		faultCode = 9002; /* Internal error */
	} else {
		debug(": success!");
	}

 out:
	unlink(fname);

	dm_add_event(EV_CPE_TRANS_COMPL, dli->command_key);
	dm_add_event(EV_CPE_DOWNLOAD, dli->command_key);
	dm_add_transfer_complete_request(
		dli->command_key,
		(struct cwmp__FaultStruct) {faultCode, NULL},
		startTime, time2ticks(time(NULL)));

	free_download_info(dli);
	cwmp_prepare_inform();
	pthread_mutex_unlock(&cwmp_mutex);

	EXIT();
	return NULL;
}

