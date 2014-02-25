/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
	libdmconfig client lib sample: uses the nonblocking libevent-based API
*/

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

void registerEndSession(DMCONTEXT *dmCtx);
void sessionTerminated(DMCONFIG_EVENT event, DMCONTEXT *dmCtx __attribute__((unused)),
		       void *user_data __attribute__((unused)), uint32_t answer_rc,
		       DIAM_AVPGRP *answer_grp __attribute__((unused)));
void listReceived(DMCONFIG_EVENT event, DMCONTEXT *dmCtx,
		  void *user_data __attribute__((unused)), uint32_t answer_rc,
		  DIAM_AVPGRP *answer_grp);
void dumpReceived(DMCONFIG_EVENT event, DMCONTEXT *dmCtx,
		  void *user_data __attribute__((unused)), uint32_t answer_rc,
		  DIAM_AVPGRP *answer_grp);
void instanceDeleted(DMCONFIG_EVENT event, DMCONTEXT *dmCtx,
		     void *user_data __attribute__((unused)), uint32_t answer_rc,
		     DIAM_AVPGRP *answer_grp __attribute__((unused)));
void instanceAdded(DMCONFIG_EVENT event, DMCONTEXT *dmCtx,
		   void *user_data __attribute__((unused)), uint32_t answer_rc,
		   DIAM_AVPGRP *answer_grp);
void parametersReceived(DMCONFIG_EVENT event, DMCONTEXT *dmCtx,
			void *user_data __attribute__((unused)), uint32_t answer_rc,
			DIAM_AVPGRP *answer_grp);
void committedChanges(DMCONFIG_EVENT event, DMCONTEXT *dmCtx,
		      void *user_data __attribute__((unused)), uint32_t answer_rc,
		      DIAM_AVPGRP *answer_grp __attribute__((unused)));
void parametersSet(DMCONFIG_EVENT event, DMCONTEXT *dmCtx,
		   void *user_data __attribute__((unused)), uint32_t answer_rc,
		   DIAM_AVPGRP *answer_grp __attribute__((unused)));
void sessionStarted(DMCONFIG_EVENT event, DMCONTEXT *dmCtx,
		    void *user_data __attribute__((unused)),
		    uint32_t answer_rc, DIAM_AVPGRP *answer_grp);
void socketConnected(DMCONFIG_EVENT event, DMCONTEXT *dmCtx,
		     void *userdata __attribute__((unused)));
int main(int argc __attribute__((unused)), char **argv __attribute__((unused)));

int counter = 0;

		/* registers END SESSION when it is called the 7. time */
void
registerEndSession(DMCONTEXT *dmCtx)
{
	if (++counter == 7) {
		if (dm_register_end_session(dmCtx, sessionTerminated, NULL))
			CB_ERR("Couldn't register END SESSION request.\n");
		printf("END SESSION registered.\n");
	}
}

void
sessionTerminated(DMCONFIG_EVENT event, DMCONTEXT *dmCtx __attribute__((unused)),
		  void *user_data __attribute__((unused)), uint32_t answer_rc,
		  DIAM_AVPGRP *answer_grp __attribute__((unused)))
{
	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't terminate session.\n");

	printf("Session terminated.\n"
	       "Returning...\n");
}

void
listReceived(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp)
{
	uint32_t	uintval, uintval2, uintval3;
	char		*charval;

	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't list object.\n");

	printf("Object listed.\n"
	       "Retrieved nodes (in \"InternetGatewayDevice\"):\n");

	while (!dm_decode_node_list(answer_grp, &charval, &uintval, &uintval2, &uintval3)) {
		switch (uintval) { /* type */
		case NODE_OBJECT:
			printf("Object(%d): ", uintval2);
			break;
		case NODE_PARAMETER:
			printf("Parameter(type:%d): ", uintval3);
			break;
		case NODE_TABLE:
			printf("Table: ");
			break;
		default:
			free(charval);
			CB_ERR("Invalid element type retrieved.\n");
		}
		printf("%s\n", charval);
		free(charval);
	}

	registerEndSession(dmCtx);
}

void
dumpReceived(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp)
{
	char *data;

	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't dump database.\n");

	printf("Data base dumped.\n");

	if (dm_decode_cmd_dump(answer_grp, &data))
		CB_ERR("Allocation error.\n");

	printf("Received data:\n%s", data);
	free(data);

	registerEndSession(dmCtx);
}

void
instanceDeleted(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp __attribute__((unused)))
{
	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't delete instance.\n");

	printf("Instance deleted.\n");

	registerEndSession(dmCtx);
}

void
instanceAdded(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp)
{
	uint16_t	instance;
	char		*charval;

	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't add instance.\n");
	printf("Instance added.\n");

	if (dm_decode_add_instance(answer_grp, &instance))
		CB_ERR("Misc error.\n");

	if (asprintf(&charval, "InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType.%u", instance) == -1)
		CB_ERR("Allocation error.\n");
	printf("New instance: %s\n", charval);

	if (dm_register_del_instance(dmCtx, charval, instanceDeleted, NULL)) {
		free(charval);
		CB_ERR("Couldn't register DELETE INSTANCE request.\n");
	}
	printf("DELETE INSTANCE request registered.\n");
	free(charval);

	registerEndSession(dmCtx);
}

void
parametersReceived(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp)
{
	int32_t		intval;
	char		*charval;
	char		*address;

	uint32_t	unknown_type, vendor_id;
	uint8_t		flags;
	void		*data;
	size_t		len;

	void		*unknown_data;
	size_t		unknown_size;

	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't get parameters.\n");
	printf("Retrieved parameters:\n");

	if (dm_decode_int32(answer_grp, &intval) ||
	    dm_decode_string(answer_grp, &charval) ||
	    diam_avpgrp_get_avp(answer_grp, &unknown_type, &flags, &vendor_id, &data, &len) ||
	    dm_decode_unknown_as_string(unknown_type, data, len, &address) ||
	    dm_decode_unknown(answer_grp, &unknown_type, &unknown_data, &unknown_size))
		CB_ERR("Allocation error.\n");

	printf("Received integer: %d\n"
	       "Received string: \"%s\"\n"
	       "Received address: %s\n"
	       "Received unknown data: %d, %p\n",
	       intval, charval, address, unknown_size, unknown_data);
	free(charval);
	free(address);
	free(unknown_data);

	registerEndSession(dmCtx);
}

void
committedChanges(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp __attribute__((unused)))
{
	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't commit changes.\n");
	printf("Changes committed.\n");

	registerEndSession(dmCtx);
}

void
parametersSet(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp __attribute__((unused)))
{
	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't set parameters.\n");
	printf("Parameters set.\n");

	if (dm_register_commit(dmCtx, committedChanges, NULL))
		CB_ERR("Couldn't register COMMIT request.\n");
	printf("COMMIT request registered.\n");

	registerEndSession(dmCtx);
}

void
sessionStarted(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *user_data __attribute__((unused)), uint32_t answer_rc, DIAM_AVPGRP *answer_grp)
{
	DIAM_AVPGRP *grp;

	if (event != DMCONFIG_ANSWER_READY || answer_rc)
		CB_ERR("Couldn't start session.\n");
	printf("Session started.\n");

	if (dm_decode_start_session(dmCtx, answer_grp))
		CB_ERR("Couldn't decode sessionid.\n");

	if (!(grp = dm_grp_new()))
		CB_ERR("Allocation error.\n");

	if (dm_grp_set_unknown(&grp, "InternetGatewayDevice.ManagementServer.PeriodicInformInterval", "42") ||
	    dm_grp_set_string(&grp, "InternetGatewayDevice.DeviceInfo.ModelName", "TEST")) {
		dm_grp_free(grp);
		CB_ERR("Allocation error.\n");
	}

	if (dm_register_packet_set(dmCtx, grp, parametersSet, NULL)) {
		dm_grp_free(grp);
		CB_ERR("Couldn't register SET request.\n");
	}
	dm_grp_free(grp);
	printf("SET request registered.\n");

	if (!(grp = dm_grp_new()))
		CB_ERR("Allocation error.\n");

	if (dm_grp_get_int32(&grp, "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPLeaseTime") ||
	    dm_grp_get_string(&grp, "InternetGatewayDevice.DeviceInfo.ManufacturerOUI") ||
	    dm_grp_get_addr(&grp, "InternetGatewayDevice.DeviceInfo.SyslogServer") ||
	    dm_grp_get_unknown(&grp, "InternetGatewayDevice.DeviceInfo.Manufacturer")) {
		dm_grp_free(grp);
		CB_ERR("Allocation error.\n");
	}

	if (dm_register_packet_get(dmCtx, grp, parametersReceived, NULL)) {
		dm_grp_free(grp);
		CB_ERR("Couldn't register GET request.\n");
	}
	dm_grp_free(grp);
	printf("GET request registered.\n");

	if (dm_register_add_instance(dmCtx, "InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType",
				     DM_ADD_INSTANCE_AUTO, instanceAdded, NULL))
		CB_ERR("Couldn't register ADD INSTANCE request.\n");
	printf("ADD INSTANCE request registered.\n");

	if (dm_register_cmd_dump(dmCtx, "", dumpReceived, NULL))
		CB_ERR("Couldn't register DUMP request.\n");
	printf("DUMP request registered.\n");

	if (dm_register_list(dmCtx, "InternetGatewayDevice", 1, listReceived, NULL))
		CB_ERR("Couldn't register LIST request.\n");
	printf("LIST request registered.\n");
}

void
socketConnected(DMCONFIG_EVENT event, DMCONTEXT *dmCtx, void *userdata __attribute__((unused)))
{
	struct timeval timeout = {.tv_sec = 20, .tv_usec = 0};

	if (event != DMCONFIG_CONNECTED)
		CB_ERR("Connecting socket unsuccessful.\n");
	printf("Socket connected.\n");

	if (dm_register_start_session(dmCtx, CMD_FLAG_CONFIGURE, NULL, &timeout, sessionStarted, NULL))
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

