
#define _GNU_SOURCE
#include <stdio.h>
#include <arpa/inet.h>
#include <stdint.h>

#include <sys/time.h>
#include <event.h>

#include <libdmconfig/dmconfig.h>

#define CB_ERR(...) {			\
	fprintf(stderr, __VA_ARGS__);	\
	return;				\
}

void activeNotification(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), DIAM_AVPGRP *grp);

void terminatedSession(DMCONFIG_EVENT event, DMCONTEXT *dmCtx __attribute__((unused)), void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp __attribute__((unused)));
void unsubscribedNotify(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp __attribute__((unused)));
void registeredNotify(DMCONFIG_EVENT event, DMCONTEXT *dmCtx __attribute__((unused)), void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp __attribute__((unused)));
void subscribedNotify(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp __attribute__((unused)));
void sessionStarted(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp);
void socketConnected(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *userdata __attribute__((unused)));
int main(int argc __attribute__((unused)), char **argv __attribute__((unused)));

			/* changing this parameter triggers the shutdown process */
#define SHUTDOWN_PARAMETER "InternetGatewayDevice.DeviceInfo.ModelName"

void
terminatedSession(DMCONFIG_EVENT event, DMCONTEXT *dmCtx __attribute__((unused)), void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp __attribute__((unused)))
{
	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't terminate session.\n");

	printf("Session terminated.\n"
	       "Returning...\n");
}

void
unsubscribedNotify(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp __attribute__((unused)))
{
	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't unsubscribe notifications.\n");
	printf("Unsubscribed notifications.\n");

	if (dm_register_end_session(dmCtx, terminatedSession, NULL))
		CB_ERR("Couldn't register END SESSION request.\n");
	printf("END SESSION request registered.\n");
}

void
activeNotification(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), DIAM_AVPGRP *grp)
{
	uint32_t type;

	if (event != DMCONFIG_ANSWER_READY)
		CB_ERR("Error while retrieving an active notification.\n");

	do {
		DIAM_AVPGRP *notify;

		if (dm_decode_notifications(grp, &type, &notify))
			CB_ERR("Couldn't decode active notifications\n")

		if (type == NOTIFY_PARAMETER_CHANGED) {
			char		*path, *str;

			uint32_t	data_type, vendor_id;
			uint8_t		flags;
			void		*data;
			size_t		len;

			if (dm_decode_parameter_changed(notify, &path, &data_type))
				CB_ERR("Couldn't decode active notifications\n");

			if (diam_avpgrp_get_avp(notify, &data_type, &flags, &vendor_id, &data, &len) ||
			    dm_decode_unknown_as_string(data_type, data, len, &str)) {
				free(path);
				CB_ERR("Couldn't decode active notifications\n");
			}

			printf("\nNotification: Parameter \"%s\" changed to \"%s\"\n", path, str);

			if (!strcmp(path, SHUTDOWN_PARAMETER)) {
				if (dm_register_unsubscribe_notify(dmCtx, unsubscribedNotify, NULL))
					CB_ERR("Couldn't register UNSUBSCRIBE NOTIFY request.\n");
				printf("UNSUBSCRIBE NOTIFY request registered.\n");
			}

			free(path);
			free(str);
		} else if (type != NOTIFY_NOTHING)
			printf("\nNotification: Warning, unknown type\n");

		dm_grp_free(notify);
	} while (type != NOTIFY_NOTHING);
}

void
registeredNotify(DMCONFIG_EVENT event, DMCONTEXT *dmCtx __attribute__((unused)), void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp __attribute__((unused)))
{
	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't register parameter notifications.\n");
	printf("Parameter notifications registered.\n");

	printf("\nThe sample program shuts down when the following parameter is modified: "
	       SHUTDOWN_PARAMETER "\n\n");
}

void
subscribedNotify(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp __attribute__((unused)))
{
	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't subscribe notifications.\n");
	printf("Subscribed notifications.\n");

	if (dm_register_recursive_param_notify(dmCtx, 1 /* active notification */, "", registeredNotify, NULL))
		CB_ERR("Couldn't register RECURSIVE PARAM NOTIFY request.\n");
	printf("RECURSIVE PARAM NOTIFY request registered.\n");
}

void
sessionStarted(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp)
{
	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't start session.\n");
	printf("Session started.\n");

	if (dm_decode_start_session(dmCtx, answer_grp))
		CB_ERR("Couldn't decode sessionid.\n");

	if (dm_register_subscribe_notify(dmCtx, activeNotification, NULL, subscribedNotify, NULL))
		CB_ERR("Couldn't register SUBSCRIBE NOTIFY request.\n");
	printf("Notification subscription request registered.\n");
}

void
socketConnected(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *userdata __attribute__((unused)))
{
	struct timeval timeout;

	if (event != DMCONFIG_CONNECTED)
		CB_ERR("Connecting socket unsuccessful.\n");
	printf("Socket connected.\n");

	memset(&timeout, 0, sizeof(struct timeval));

	if (dm_register_start_session(dmCtx, CMD_FLAG_READWRITE, &timeout, NULL, sessionStarted, NULL))
		CB_ERR("Couldn't register start session request.\n");
	printf("Start session request registered.\n");
}

int
main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
	DMCONTEXT		dmCtx;
	struct event_base	*base;

	if (!(base = event_init())) {
		fprintf(stderr, "Couldn't initialize event base.\n");
		return 0;
	}
	printf("Event base initialized.\n");

	dm_context_init(&dmCtx, base);

	if (dm_create_socket(&dmCtx, AF_INET)) {
		fprintf(stderr, "Couldn't create socket.\n");
		event_base_free(base);
		return 0;
	}
	printf("Socket created.\n");

	if (dm_register_connect_callback(&dmCtx, AF_INET, socketConnected, NULL)) {
		fprintf(stderr, "Couldn't register connect callback or connecting unsuccessful.\n");
		dm_shutdown_socket(&dmCtx);
		event_base_free(base);
		return 0;
	}
	printf("Connect callback registered.\n");

	event_base_dispatch(dm_context_get_event_base(&dmCtx));

	dm_shutdown_socket(&dmCtx);
	printf("Socket shut down.\n");
	event_base_free(base);
	printf("Event base freed.\n");

	return 0;
}

