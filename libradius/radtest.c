#include <assert.h>

#include <stdlib.h>
#include <stdio.h>
#include <event.h>

#include "radlib.h"
#include "radlib_vs.h"

struct rad_handle *new_auth(const char *user, const char *passwd, const char *class)
{
	struct rad_handle *h;

	h = rad_auth_open(strdup(class));
	assert(h);

	rad_create_request(h, RAD_ACCESS_REQUEST);

	// rad_put_addr(radh, RAD_NAS_IP_ADDRESS, extip);
	rad_put_string(h, RAD_NAS_IDENTIFIER, "TEST-NAS");

	rad_put_int   (h, RAD_NAS_PORT,           1); 
	rad_put_int   (h, RAD_SERVICE_TYPE,       RAD_FRAMED);
	rad_put_int   (h, RAD_FRAMED_PROTOCOL,    RAD_PPP);
	rad_put_string(h, RAD_CALLING_STATION_ID, "DE:AD:BE:EF:00:01");
	rad_put_string(h, RAD_CALLED_STATION_ID,  "BE:EF:00:00:DE:AD");

	rad_put_string(h, RAD_USER_NAME, user);
	rad_put_string(h, RAD_USER_PASSWORD, passwd);
	rad_put_string(h, RAD_ACCT_SESSION_ID, "00000000000");

	rad_put_vendor_string(h, RAD_VENDOR_TRAVELPING, RAD_TRAVELPING_USERAGENT,
			      "Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.9.0.2pre) Gecko/2008070419 Firefox/3.0.2pre (Swiftfox)");
	rad_put_vendor_string(h, RAD_VENDOR_DSLF, RAD_DSLF_AGENT_CIRCUIT_ID,
			      "Circuit Id");
	rad_put_vendor_string(h, RAD_VENDOR_DSLF, RAD_DSLF_AGENT_REMOTE_ID,
			      "Remote Id");

	return h;
}

void notify_cb(int res, struct rad_handle *h, void *user, void *data)
{
	printf("got response %d for %s\n", res, data ? data : "NULL");
	fflush(stdout);

	free(data);
	rad_close(h);
}

int main(void)
{
	int i;
	int rc;
	struct rad_setup *auths;
	struct rad_setup *accts;

	event_init();
	rad_init();

	auths = rad_setup_open(RADIUS_AUTH, notify_cb, NULL);
	accts = rad_setup_open(RADIUS_ACCT, notify_cb, NULL);

	printf("Auth Server: %p\n", auths);
	printf("Acct Server: %p\n", auths);

	assert(auths);
	assert(accts);

//	rc = rad_new_server(auths, "192.168.2.24", 1812, "secret", 8, 3);
	printf("new Auth Server rc: %d\n", rc);

//	rc = rad_new_server(accts, "192.168.2.24", 1813, "secret", 8, 3);
	printf("new Acct Server rc: %d\n", rc);

	/*
	 * library load test
	 */
	for (i = 0; i < 10; i++) {
		char user[256];
		char passwd[256];
		char class[256];
		struct rad_handle *h;

		snprintf(user,   256, "User-Name-%08d", i);
		snprintf(passwd, 256, "Password-%08d", i);
		snprintf(class, 256,  "Class-%08d", i);

		h = new_auth(user, passwd, class);
		rad_send_request(auths, h);
	}

	event_dispatch();
}
