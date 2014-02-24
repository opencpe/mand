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

#include <string.h>

#include "dm_cfg_bkrst.h"
#include "dm_signature.h"
#include "dm_validate.h"

#include "process.h"

#define SDEBUG
#include "debug.h"

#define SIGNED_CONFIG	"/tmp/signed.cfg"
#define DM_CONFIG	"/jffs/etc/dm.xml"

DM_RESULT save_conf(char *url)
{
	char *host, *path;
	int port, rc;

	ENTER(": url: \"%s\"", url);

	rc = parse_tftp_url(url, &host, &path, &port);
	if (rc < 0) {
		EXIT();
		return DM_INVALID_VALUE;
	}
	debug("(): host: \"%s\", path: \"%s\", port: %d", host, path, port);

	if (sign_file(DM_CONFIG, SIGNED_CONFIG)) {
		EXIT();
		return DM_FILE_NOT_FOUND;
	}

	/*
	 * NOTE: parse_tftp_url() does not permit any character in "host" or "path"
	 * that may be used to exploit the shell. It does permit spaces in "path"
	 * though.
	 */
	rc = vasystem("tftp -p -l %s -r \"%s%s\" \"%s\" %d",
		      SIGNED_CONFIG,
		      path, rc == DEFAULTFILE ? SIGNED_CONFIG + 5 : "",
		      host, port);

	unlink(SIGNED_CONFIG);

	EXIT();
	return rc ? DM_ERROR : DM_OK;
}

DM_RESULT restore_conf(char *url)
{
	char *host, *path;
	int port, rc;

	ENTER(": url: \"%s\"", url);

	rc = parse_tftp_url(url, &host, &path, &port);
	if (rc < 0) {
		EXIT();
		return DM_INVALID_VALUE;
	}
	debug("(): host: \"%s\", path: \"%s\", port: %d", host, path, port);

	/* NOTE: see above */
	rc = vasystem("tftp -g -r \"%s%s\" -l %s \"%s\" %d",
		      path, (rc == DEFAULTFILE) ? SIGNED_CONFIG + 5 : "",
		      SIGNED_CONFIG, host, port);
	if (rc) {
		EXIT();
		return DM_ERROR;
	}

	rc = validate_file(SIGNED_CONFIG, DM_CONFIG);

	unlink(SIGNED_CONFIG);

	EXIT_MSG(": rc: %d", rc);
	return rc ? DM_FILE_NOT_FOUND : DM_OK;
}
