/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
	libdmconfig sample that demonstrates polling in a read-only session
*/

#define _GNU_SOURCE
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <event.h>

#include <libdmconfig/dmconfig.h>

#define DELAY 1 /* 1 second */

int
main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
	DMCONTEXT		ctx;

	struct event_base	*base;

	struct timeval		timeout;

	if (!(base = event_init())) {
		fprintf(stderr, "Couldn't initiate event base\n");
		return 1;
	}
	printf("Event base initialized\n");

	dm_context_init(&ctx, base);

	if (dm_init_socket(&ctx, AF_INET)) {
		fprintf(stderr, "Couldn't initiate server connection\n");
		return 1;
	}
	printf("Connection initiated\n");

			/* open read/write session */

	memset(&timeout, 0, sizeof(struct timeval));

	if (dm_send_start_session(&ctx, CMD_FLAG_READWRITE, &timeout, NULL)) {
		fprintf(stderr, "An error occurred: Couldn't initiate session context\n");
		return 1;
	}
	printf("\"Start session\" was successful\n");

	if (dm_send_subscribe_notify(&ctx)) {
		fprintf(stderr, "Couldn't subscribe notifications\n");
		return 1;
	}
	printf("\"Subscribe notify\" was successful\n");

	if (dm_send_recursive_param_notify(&ctx, 0, "")) {
		fprintf(stderr, "Couldn't register parameter notifications\n");
		return 1;
	}
	printf("\"Recursive register param notify\" was successful\n");

	printf("Polling. Terminate by pressing CTRL-C");
	fflush(stdout);

	do {
		DM_AVPGRP	*events;
		uint32_t	type;

		switch (dm_send_get_passive_notifications(&ctx, &events)) {
		case RC_OK:
			break;
		case RC_ERR_INVALID_SESSIONID:
			printf("\nEVENT: Session timed out. Returning...\n");
			return 0;
		default:
			fprintf(stderr, "\nAn error occurred: Couldn't poll (get passive notifications)\n");
			return 1;
		}

		do {
			DM_AVPGRP *notify;

			if (dm_decode_notifications(events, &type, &notify)) {
				dm_grp_free(events);
				fprintf(stderr, "\nAn error occurred: Couldn't decode polling results\n");
				return 1;
			}
			if (type == NOTIFY_PARAMETER_CHANGED) {
				char		*path, *str;

				uint32_t	data_type, vendor_id;
				uint8_t		flags;
				void		*data;
				size_t		len;

				if (dm_decode_parameter_changed(notify, &path, &data_type)) {
					dm_grp_free(events);
					fprintf(stderr, "\nAn error occurred: Couldn't decode polling results\n");
					return 1;
				}

				if (dm_avpgrp_get_avp(notify, &data_type, &flags, &vendor_id, &data, &len) ||
				    dm_decode_unknown_as_string(data_type, data, len, &str)) {
					free(path);
 					dm_grp_free(events);
					fprintf(stderr, "\nAn error occurred: Couldn't decode polling results\n");
					return 1;
				}

				printf("\nNotification: Parameter \"%s\" changed to \"%s\"\n", path, str);
				free(path);
				free(str);
			} else if (type != NOTIFY_NOTHING)
				printf("\nNotification: Warning, unknown type\n");

			dm_grp_free(notify);
		} while (type != NOTIFY_NOTHING);

		dm_grp_free(events);

		printf(".");
		fflush(stdout);
	} while (!sleep(DELAY));

	if (dm_send_unsubscribe_notify(&ctx)) {
		fprintf(stderr, "\nCouldn't unsubscribe notification\n");
		return 1;
	}
	printf("\n\"Unsubscribe notify\" was successful\n");

	if (dm_send_end_session(&ctx)) {
		fprintf(stderr, "\nAn error occurred: Couldn't terminate session context\n");
		return 1;
	}
	printf("\n\"End session\" was successful\n");

	dm_shutdown_socket(&ctx);
	printf("Connection terminated.\n");

	event_base_free(base);
	printf("Event base freed\n");

	return 0;
}
