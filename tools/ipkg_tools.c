#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

#include "ftools.h"
#include "ipkg_tools.h"

#if defined (HAVE_LIBPOLARSSL)
#include "polarssl/sha1.h"
#include "polarssl/x509.h"

#define SHA1_SIZE 20

#define SHA1_CTX sha1_context

#define SHA1Init sha1_starts
#define SHA1Update sha1_update
#define SHA1Final sha1_finish
#endif

#define chomp(s)							\
	({								\
		char *c = (s) + strlen((s)) - 1;			\
		while ((c > (s)) && (*c == '\n' || *c == '\r' || *c == ' ')) \
			*c-- = '\0';					\
		s;							\
	})

#define min(x, y)  ((x > y) ? y : x)

#if defined (HAVE_LIBPOLARSSL)

int validate_ipkg(const char *fname)
{
	FILE *inf;
	x509_cert cert;
	SHA1_CTX ctx;
	uint8_t digest[SHA1_SIZE];
	unsigned char *fbuf;
	long fsize, rest;
	int sum, n;
	int r = 0;

	memset(&cert, 0, sizeof(cert));

	if (x509parse_crtfile(&cert, "/etc/ssl/tplino.crt") != 0) {
		r = ERR_CRIT_CERT_READ;
		fw_finish(r, "reading the certificat failed");
		return r;
	}

	inf = fopen(fname, "r");
	if (!inf) {
		perror("fopen");
		return ERR_CRIT_ERROR;
	}

	fseek(inf, 0, SEEK_END);
	fsize = ftell(inf) - cert.rsa.len;
	fseek(inf, 0, SEEK_SET);

	fbuf = malloc(16*1024);

	/* calculate SHA1 over fw */
	SHA1Init(&ctx);

	sum = 0;
	for (rest = fsize; rest > 0;) {
		int l = min(16 * 1024, rest);

		n = fread(fbuf, 1, l, inf);
		if (n != l)
			break;

		fw_progress("Calculating SHA1", STEP_SIGN, KB(fsize), KB(sum), "k");

		sum += n;
		SHA1Update(&ctx, fbuf, n);
		rest -= n;
	}
	SHA1Final(&ctx, digest);

	fw_progress("Calculating SHA1", STEP_SIGN, KB(fsize), KB(fsize), "k");

	n = fread(fbuf, 1, 16 * 1024, inf);
	if (n > 0) {

		r = rsa_pkcs1_verify(&cert.rsa, RSA_PUBLIC, RSA_SHA1, SHA1_SIZE, digest, fbuf);
		if (r != 0) {
			r = ERR_CRIT_SIGN_MATCH;
			fw_finish(r, "image does not match signature");
		}
	} else {
		r = ERR_CRIT_ERROR;
		fw_finish(r, "error reading signature");
	}
	fclose(inf);
	free(fbuf);

	return r;
}

#else

int validate_ipkg(const char *fname)
{
	return 0;
}

#endif

static int vasystem(int echo, const char *fmt, ...)
{
        va_list args;
        char    buf[1024];

        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);

	if (echo)
		fprintf(stderr, "exec: %s\n", buf);
	return system(buf);
}

static int pkg_name_len(const char *fname)
{
	char *p;

	p = strchr(fname, '_');
	if (p)
		return p - fname;

	return strlen(fname);
}

int install_ipkg(const char *fname, int verbose)
{
	struct stat istat;
	char tmpdir[] = "/tmp/ipkg.XXXXXX";
	char lname[1024];
	const char *pname;
	int plen;
	int rc;

	pname = strrchr(fname, '/');
	if (!pname)
		pname = fname;
	plen = pkg_name_len(pname);

	snprintf(lname, sizeof(lname), "%s/%.*s.list", IPKG_PLIST_DIR , plen, pname);
	if (stat(lname, &istat) != -1) {
		fw_finish(ERR_CRIT_ERROR, "ipkg already installed");
		return ERR_CRIT_ERROR;
	}

	/* create temp work dir */
	mkdtemp(tmpdir);

	/* extract package */
	rc = vasystem(verbose, "/bin/tar -C %s -xzf %s", tmpdir, fname);
	if (rc != 0) {
		fw_finish(ERR_CRIT_IPKG_UNTAR, "untar of ipkg failed with %d", rc);
		return ERR_CRIT_IPKG_UNTAR;
	}

	/* build list of files and install at the same time */
	rc = vasystem(verbose, "/bin/tar -C %s -xvzf %s/data.tar.gz > %s/%.*s.list", IPKG_INSTALL_ROOT, tmpdir, IPKG_PLIST_DIR, plen, pname);
	if (rc != 0) {
		fw_finish(ERR_CRIT_DATA_UNTAR, "untar of data pkg failed with %d", rc);
		return ERR_CRIT_DATA_UNTAR;
	}

	/* clean up */
	rc = vasystem(verbose, "rm -rf %s", tmpdir);

	/* TODO: remember installed package somewhere */

	fw_finish(0, "success");
	return 0;
}

int remove_ipkg(const char *pkg_name, int verbose)
{
	int r = 0;
	int fd;
	char lname[1024];
	struct stat istat;
	unsigned char *buf, *s;

	snprintf(lname, sizeof(lname), "%s/%s.list", IPKG_PLIST_DIR , pkg_name);
	fd = open(lname, O_RDONLY);
	if (fd == -1) {
		fw_finish(ERR_CRIT_ERROR, "failed to open %s: %m (%d)", lname, errno);
		return 0;
	}

	if (fstat(fd, &istat) == -1)
		goto out;

	buf = mmap(NULL, istat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (!buf) {
		r = ERR_CRIT_ERROR;
		fw_finish(r, "mmap of %d failed: %m (%d)", istat.st_size, errno);
		goto out;
	}
	unlink(lname);

	s = buf + istat.st_size;
	while (s > buf) {
		int len, rc;
		char *p;
		struct stat rstat;

		s--;
		for (len = 0; s > buf && *s != '\n'; s--, len++)
			;
		if (len == 0)
			continue;
		    
		p = s;

		if (*p == '\n')
			p++;
		else
			len++;

		snprintf(lname, sizeof(lname), "%s/%.*s", IPKG_INSTALL_ROOT, len, p);
		if (verbose)
			fprintf(stderr, "removing %s...", lname);

		if (stat(lname, &rstat) == -1) {
			if (verbose)
				fprintf(stderr, "not found\n");
			continue;
		}

		if ((rstat.st_mode & S_IFMT) == S_IFDIR)
			rc = rmdir(lname);
		else
			rc = unlink(lname);

		if (verbose)
			fprintf(stderr, "%s\n", rc == 0 ? "ok" : "fail");
	}

	munmap(buf, istat.st_size);
	fw_finish(r, "success");

out:
	close(fd);
	return r;
}
