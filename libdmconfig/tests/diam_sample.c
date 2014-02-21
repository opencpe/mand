/* diammsg sample */

#ifdef LIBDMCONFIG_DEBUG

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#include <talloc/talloc.h>

#include <libdmconfig/diammsg.h>
#include <libdmconfig/debug.h>

#include <libdmconfig/codes.h>

int
main(int argc __attribute__((unused)), char **argv __attribute__((unused))) {
	DIAM_REQUEST	*req;
	DIAM_AVPGRP	*grp;
	DIAM_AVPGRP	*pair;

	uint32_t	hop2hop = 0;
	uint32_t	end2end = 0;

	const char	p1[] = "InternetGatewayDevice.DeviceInfo.ManufacturerOUI";
	const char	p2[] = "InternetGatewayDevice.DeviceInfo.ModelName";

	void		*buf1, *buf2;
	int		size1, size2;

			/* GET command */

	if(!(req = new_diam_request(NULL, CMD_DB_GET, CMD_FLAG_REQUEST, APP_ID, hop2hop, end2end)))
		return 1;
	if(!(grp = new_diam_avpgrp(req)) ||
	   !(buf1 = malloc(size1 = strlen(p1) + 4)) ||!(buf2 = malloc(size2 = strlen(p2) + 4))) {
		talloc_free(req);
		return 1;
	}
	*(uint32_t*)buf1 = *(uint32_t*)buf2 = htonl(AVP_STRING);
	memcpy(buf1 + 4, p1, size1 - 4);
	memcpy(buf2 + 4, p2, size2 - 4);
	diam_avpgrp_add_raw(req, &grp, AVP_TYPE_PATH, 0, VP_TRAVELPING, buf1, size1);
	diam_avpgrp_add_raw(req, &grp, AVP_TYPE_PATH, 0, VP_TRAVELPING, buf2, size2);
	free(buf1);
	free(buf2);
	build_diam_request(NULL, &req, grp);

	dump_diam_packet(req);

	talloc_free(req);

			/* SET command */

	if(!(req = new_diam_request(NULL, CMD_DB_SET, CMD_FLAG_REQUEST, APP_ID, hop2hop, end2end)))
		return 1;
	if(!(grp = new_diam_avpgrp(req)) || !(pair = new_diam_avpgrp(grp))) {
		talloc_free(req);
		return 1;
	}

	diam_avpgrp_add_string(grp, &pair, AVP_PATH, 0, VP_TRAVELPING, p1);
	diam_avpgrp_add_string(grp, &pair, AVP_STRING, 0, VP_TRAVELPING, "test value for ManufacturerOUI");
	diam_avpgrp_add_avpgrp(req, &grp, AVP_CONTAINER, 0, VP_TRAVELPING, pair);
	talloc_free(pair);

	if(!(pair = new_diam_avpgrp(grp))) {
		talloc_free(req);
		return 1;
	}
	diam_avpgrp_add_string(grp, &pair, AVP_PATH, 0, VP_TRAVELPING, p2);
	diam_avpgrp_add_string(grp, &pair, AVP_STRING, 0, VP_TRAVELPING, "test value for ModelName");
	diam_avpgrp_add_avpgrp(req, &grp, AVP_CONTAINER, 0, VP_TRAVELPING, pair);
	build_diam_request(NULL, &req, grp);

	dump_diam_packet(req);

	talloc_free(req);

	return 0;
}

#else

#include <stdio.h>

int
main(int argc __attribute__((unused)), char **argv __attribute__((unused))) {
	printf("This is only a dummy\n"
	       "libdmconfig and diam_sample must be compiled with the LIBDMCONFIG_DEBUG macro\n");
	return 0;
}

#endif
