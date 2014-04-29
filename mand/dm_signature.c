/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dm_signature.h"

#if defined (HAVE_LIBPOLARSSL)
#include <polarssl/base64.h>
#include "polarssl/sha1.h"
#include "polarssl/x509.h"

#define SHA1_SIZE 20

#define SHA1_CTX sha1_context

#define SHA1Init sha1_starts
#define SHA1Update sha1_update
#define SHA1Final sha1_finish

#elif defined (HAVE_LIBAXTLS)
#include "axtls-config.h"
#include "ssl.h"
#endif

#define SIGN_START "------ TPLINO SIGNED DATA BEGIN ------\n"
#define SIGN_END   "------ TPLINO SIGNED DATA END ------\n"

#define SIGN_CERT         -1
#define SIGN_MISMATCH     -2
#define SIGN_NOT_AUTH     -3

#if defined (HAVE_LIBPOLARSSL)

static int check_signature(unsigned char *hash, int hashlen,
			   unsigned char *sig,  int siglen __attribute__ ((unused)))
{
	int r;
	x509_cert cert;

	memset(&cert, 0, sizeof(cert));

	if (x509parse_crtfile(&cert, "/etc/ssl/cpe.crt") != 0)
		return SIGN_CERT;

	r = rsa_pkcs1_verify(&cert.rsa, RSA_PUBLIC, RSA_SHA1, hashlen, hash, sig);
	if (r != 0)
		r = SIGN_MISMATCH;

	return r;
}

static int sign_digest(unsigned char *hash, int hashlen,
		       unsigned char *sig,  int *siglen)
{
	int r;
	rsa_context rsa;

	memset(&rsa, 0, sizeof(rsa));

	if (x509parse_keyfile(&rsa, "/etc/ssl/cpe.key", NULL) != 0)
		return SIGN_CERT;

	r = rsa_pkcs1_sign(&rsa, RSA_PRIVATE, RSA_SHA1, hashlen, hash, sig);
	*siglen = rsa.len;

	return r;
}

#endif

/**
 * copy source to dest adding a TPLINO signature
 */
int sign_file(const char *source __attribute__ ((unused)), const char *dest __attribute__ ((unused)))
{
#if 0 /* TODO */
	int fin, fout;
	int n, r;
	int res = -1;
	SHA1_CTX ctx;
	uint8_t digest[SHA1_SIZE];
	char buf[4096];

	fin = open(source, O_RDONLY);
	if (fin < 0)
		return -1;

	fout = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0664);
	if (fout < 0) {
		close(fin);
		return -1;
	}

	r = write(fout, SIGN_START, strlen(SIGN_START));
	if (r != strlen(SIGN_START))
		goto out;

	SHA1Init(&ctx);

	do {
		n = read(fin, buf, sizeof(buf));
		if (n <= 0)
			break;

		SHA1Update(&ctx, (uint8_t *)&buf, n);
		r = write(fout, buf, n);
		if (r != n)
			goto out;
	} while (r > 0);

	SHA1Final(&ctx, digest);

	r = write(fout, SIGN_END, strlen(SIGN_END));
	if (r != strlen(SIGN_END))
		goto out;

	res = sign_digest(digest, SHA1_SIZE, buf, &n);
	if (res != 0)
		goto out;

	r = sizeof(buf) - n;
	if (base64_encode(buf + n, &r, buf, n) != 0)
		goto out;

	r += n;
	for (; n < r; n += 64)
                if (dprintf(fout,"%.64s\n", &buf[n]) < 0)
			goto out;

	res = 0;
out:
	close(fin);
	close(fout);
	if (res != 0)
		unlink(dest);

	return res;
#endif
	return 0;
}

/**
 * copy source to dest validating a TPLINO signature
 */
int validate_file(const char *source __attribute__ ((unused)), const char *dest __attribute__ ((unused)))
{
#if 0 /* TODO */
	FILE *fin, *fout;
	int r;
	char *p;
	int res = -1;
	SHA1_CTX ctx;
	uint8_t digest[SHA1_SIZE];
	char buf[4096];

	fin = fopen(source, "r");
	if (!fin)
		return -1;

	fout = fopen(dest, "w");
	if (!fout) {
		fclose(fin);
		return -1;
	}

	if (!fgets(buf, sizeof(buf), fin))
		goto out;

	if (strcmp(buf, SIGN_START) != 0)
		goto out;

	SHA1Init(&ctx);

	while (42) {
		if (!fgets(buf, sizeof(buf), fin)) {
			goto out;
		}

		if (strcmp(buf, SIGN_END) == 0)
			break;

		SHA1Update(&ctx, (uint8_t *)&buf, strlen(buf));

		if (fwrite(buf, strlen(buf), 1, fout) != 1) {
			goto out;
		}
	}


	SHA1Final(&ctx, digest);

	r = sizeof(buf);
	p = &buf[0];
	while ((p = fgets(p, r, fin))) {
		int l = strlen(p);
		p += l;
		r -= l;
	}

	r = sizeof(buf);
	base64_decode(buf, &r, buf, strlen(buf));

	res = check_signature(digest, SHA1_SIZE, buf, r);

out:
	fclose(fin);
	fclose(fout);
	if (res != 0)
		unlink(dest);

	return res;
#endif
	return 0;
}
