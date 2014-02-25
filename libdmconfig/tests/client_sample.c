/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/*
	sample for the libdmconfig frontend library (protocol's client side)
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <arpa/inet.h>
#include <stdint.h>

#include <sys/time.h>
#include <event.h>

#include <libdmconfig/dmconfig.h>

int
main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
	DMCONTEXT		ctx;

	struct event_base	*base;

	DIAM_AVPGRP		*grp;
	DIAM_AVPGRP		*ret_grp;

	uint16_t		uint16val;
	int32_t			intval;
	uint32_t		uintval, uintval2, uintval3;
	char			*charval;
	char			*address;

	uint32_t		unknown_type, vendor_id;
	uint8_t			flags;
	void			*data;
	size_t			len;

	void			*unknown_data;
	size_t			unknown_size;

	struct timeval		timeout = {.tv_sec = 20, .tv_usec = 0};

	if (!(base = event_init())) {
		fprintf(stderr, "Couldn't initiate event base\n");
		return 1;
	}
	printf("Event base initiated\n");

	dm_context_init(&ctx, base);

	if (dm_init_socket(&ctx, AF_INET)) {
		fprintf(stderr, "An error occurred: Couldn't initiate server connection\n");
		event_base_free(base);
		return 1;
	}
	printf("Connection initiated\n");

			/* open configure session */

	if (dm_send_start_session(&ctx, CMD_FLAG_CONFIGURE, NULL, &timeout)) {
		fprintf(stderr, "An error occurred: Couldn't initiate session context\n");
		dm_shutdown_socket(&ctx);
		event_base_free(base);
		return 1;
	}
	printf("\"Start session\" was successful\n");

			/* set some parameters */

	if (!(grp = dm_grp_new())) {
		fprintf(stderr, "An error occurred: Couldn't create new AVP group\n");
		goto abort;
	}

#define SIZE 8*1024*1
	char *dum = malloc(SIZE);
	memset(dum, 'X', SIZE - 1);
	dum[SIZE-1] = '\0';

	if (dm_grp_set_unknown(&grp, "InternetGatewayDevice.ManagementServer.PeriodicInformInterval", "42") ||
	    dm_grp_set_string(&grp, "InternetGatewayDevice.DeviceInfo.ModelName", dum) ||
	    dm_send_packet_set(&ctx, grp)) {
		fprintf(stderr, "An error occurred: Couldn't create or send SET packet\n");
		dm_grp_free(grp);
		goto abort;
	}
	printf("\"Set\" request was successful\n");

	dm_grp_free(grp);

	free(dum);

	if (dm_send_commit(&ctx)) {
		fprintf(stderr, "An error occurred: Couldn't commit changes\n");
		goto abort;
	}
	printf("\"Commit\" request was successful\n");

		/* switch session to read/write mode
		   just for demonstration purposes */

	if (dm_send_switch_session(&ctx, CMD_FLAG_READWRITE, NULL, NULL)) {
		fprintf(stderr, "An error occurred: Couldn't switch from read/write to read-only mode\n");
		goto abort;
	}
	printf("\"Switch session\" was successful\n");

		/* retrieve some parameters */

	if (!(grp = dm_grp_new())) {
		fprintf(stderr, "An error occurred: Couldn't create new AVP group\n");
		goto abort;
	}

	if (dm_grp_get_int32(&grp, "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPLeaseTime") ||
	    dm_grp_get_string(&grp, "InternetGatewayDevice.DeviceInfo.ModelName") ||
	    dm_grp_get_addr(&grp, "InternetGatewayDevice.DeviceInfo.SyslogServer") ||
	    dm_grp_get_unknown(&grp, "InternetGatewayDevice.DeviceInfo.Manufacturer") ||
	    dm_send_packet_get(&ctx, grp, &ret_grp) ||
	    dm_decode_int32(ret_grp, &intval) ||
	    dm_decode_string(ret_grp, &charval) ||
	    diam_avpgrp_get_avp(ret_grp, &unknown_type, &flags, &vendor_id, &data, &len) ||
	    dm_decode_unknown_as_string(unknown_type, data, len, &address) ||
	    dm_decode_unknown(ret_grp, &unknown_type, &unknown_data, &unknown_size)) {
		fprintf(stderr, "An error occurred: Couldn't create, send or decode GET packet\n");
		dm_grp_free(grp);
		goto abort;
	}
	printf("\"Get\" request was successful\n"
	       "Received integer: %d\n"
	       "Received string: \"%s\"\n"
	       "Received address: %s\n"
	       "Received unknown data: %d, %p\n",
	       intval, charval, address, unknown_size, unknown_data);
	free(charval);
	free(address);
	free(unknown_data);

	dm_grp_free(grp);

		/* switch session back to configure mode */

	if (dm_send_switch_session(&ctx, CMD_FLAG_CONFIGURE, NULL, &timeout)) {
		fprintf(stderr, "An error occurred: Couldn't switch from read-only to read/write mode\n");
		goto abort;
	}
	printf("\"Switch session\" was successful\n");

	if (dm_send_get_session_info(&ctx, &uintval)) {
		fprintf(stderr, "An error occurred: Couldn't retrieve the current session flags\n");
		goto abort;
	}
	printf("\"Get session info\" was successful\n"
	       "Received session flags: %u\n", uintval);

		/* add an object instance and delete it afterwards */

	uint16val = DM_ADD_INSTANCE_AUTO;
	if (dm_send_add_instance(&ctx, "InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType", &uint16val)) {
		fprintf(stderr, "An error occurred: Couldn't add an interface instance\n");
		goto abort;
	}
	if (asprintf(&charval, "InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType.%u", uint16val) == -1) {
		fprintf(stderr, "An error occurred: Allocation error\n");
		goto abort;
	}
	printf("\"Add instance\" request was successful\n"
	       "New instance: %s\n", charval);

	if (dm_send_del_instance(&ctx, charval)) {
		free(charval);
		fprintf(stderr, "An error occurred: Couldn't delete object instance\n");
		goto abort;
	}
	printf("\"Delete instance\" request was successful\n"
	       "Deleted instance: %s\n", charval);
	free(charval);

	if (!(grp = dm_grp_new()) ||
	    dm_grp_set_string(&grp, "Name", "br") ||
	    dm_send_find_instance(&ctx, "InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType", grp, &uint16val)) {
		dm_grp_free(grp);
		fprintf(stderr, "An error occurred: Couldn't build/send/eval FIND_INSTANCE request\n");
		goto abort;
	}
	dm_grp_free(grp);

	printf("\"Find instance\" request was successful\n"
	       "Found instance: %u\n", uint16val);

		/* some other commands/requests */

	if (dm_send_cmd_dump(&ctx, "", &charval)) {
		fprintf(stderr, "An error occurred: Couldn't retrieve database dump\n");
		goto abort;
	}
	printf("\"Dump\" request was successful\n"
	       "Recieved data:\n%s", charval);
	free(charval);

	if (dm_send_list(&ctx, "InternetGatewayDevice", 1, &ret_grp)) {
		fprintf(stderr, "An error occurred: Couldn't retrieve node list\n");
		goto abort;
	}
	printf("\"List\" request was successful\n"
	       "Retrieved nodes (in \"InternetGatewayDevice\"):\n");
	while (!dm_decode_node_list(ret_grp, &charval, &uintval, &uintval2, &uintval3)) {
		switch(uintval) { /* type */
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
			fprintf(stderr, "An error occurred: Invalid node type retrieved\n");
			free(charval);
			dm_grp_free(ret_grp);
			goto abort;
		}
		printf("%s\n", charval);
		free(charval);
	}
	dm_grp_free(ret_grp);

		/* close session */

	if (dm_send_end_session(&ctx)) {
		fprintf(stderr, "An error occurred: Couldn't terminate session context\n");
		dm_shutdown_socket(&ctx);
		event_base_free(base);
		return 1;
	}
	printf("\"End session\" request was successful\n");

	dm_shutdown_socket(&ctx);
	printf("Connection terminated.\n");

	event_base_free(base);
	printf("Event base freed\n");

	return 0;

abort:

	dm_send_end_session(&ctx);
	dm_shutdown_socket(&ctx);
	event_base_free(base);

	return 1;
}

