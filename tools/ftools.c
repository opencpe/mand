#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "crc.h"
#include "ftools.h"

#if defined (HAVE_LIBPOLARSSL)
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

#define min(x, y)  ((x > y) ? y : x)

size_t safe_fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
        size_t ret = 0;

        do {
                clearerr(stream);
                ret += fread((char *)ptr + (ret * size), size, nmemb - ret, stream);
        } while (ret < nmemb && ferror(stream) && errno == EINTR);

        return ret;
}

size_t safe_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
        size_t ret = 0;

        do {
                clearerr(stream);
                ret += fwrite((char *)ptr + (ret * size), size, nmemb - ret, stream);
        } while (ret < nmemb && ferror(stream) && errno == EINTR);

        return ret;
}

static int scan_config(char *fname, unsigned char **brand, unsigned char **device)
{
	FILE *inf;
	char buf[1024];
	inf = fopen(fname, "r");
	if (!inf)
		return 0;

	while (!feof(inf)) {
		int l;
		char *s;

		if (fgets(buf, sizeof(buf), inf) == NULL)
			break;

		s = strchr(buf, '=');
		if (!s)
			continue;

		*s++ = '\0';
		while (*s && isspace(*s))
		       s++;
		l = strlen(s);
		while (l > 1 && isspace(s[l - 1]))
			l--;
		s[l] = '\0';

		if (strcasecmp(buf, "FW_VARIANT") == 0) {
			*brand = strdup(s);
		} else if (strcasecmp(buf, "FW_DEVICE") == 0) {
			*device = strdup(s);
		}
	}
	fclose(inf);
	
	return (*brand && *device);
}

#define SIGN_CERT         -1
#define SIGN_MISMATCH     -2
#define SIGN_NOT_AUTH     -3

#if defined (HAVE_LIBPOLARSSL)

static int check_signature(unsigned char *hash, int hashlen,
			   unsigned char *sig,  int siglen)
{
	int r;
	x509_cert cert;

	memset(&cert, 0, sizeof(cert));

	if (x509parse_crtfile(&cert, "/etc/ssl/tplino.crt") != 0)
		return SIGN_CERT;

	r = rsa_pkcs1_verify(&cert.rsa, RSA_PUBLIC, RSA_SHA1, hashlen, hash, sig);
	if (r != 0)
		r = SIGN_MISMATCH;

	return r;
}

#elif defined (HAVE_LIBAXTLS)

static int check_signature(unsigned char *hash, int hashlen,
			   unsigned char *sig,  int siglen)
{
	X509_CTX *x509_ctx;
	
	BI_CTX *ctx;
	bigint *mod, *expn;
	bigint *cert_sig;
	bigint *bi_digest;
	
	int len;
	uint8_t *buf;
	int r = 0;
	
	if (get_file("/etc/ssl/tplino.crt", &buf) < 0 ||
	    x509_new(buf, &len, &x509_ctx)) {
		return SIGN_CERT;
	}
	
	/* check the signature */
	ctx = x509_ctx->rsa_ctx->bi_ctx;
	mod = x509_ctx->rsa_ctx->m;
	expn = x509_ctx->rsa_ctx->e;
	
	cert_sig = RSA_sign_verify(ctx, sig, siglen,
				   bi_clone(ctx, mod), bi_clone(ctx, expn));
	
	if (cert_sig) {
		bi_digest = bi_import(ctx, hash, hashlen);
		
		if (bi_compare(cert_sig, bi_digest) != 0)
			r = SIGN_MISMATCH;
		
		bi_free(ctx, bi_digest);
		bi_free(ctx, cert_sig);
	} else
		r = SIGN_NOT_AUTH
	
	x509_free(x509_ctx);
	free(buf);

	return r;
}

#endif

int validate_tpfu(FILE *inf, int *fsize)
{
	int r = 0;
	int size, rest, sum;
	SHA1_CTX ctx;
	uint8_t digest[SHA1_SIZE];
	uint32_t crc32 = CRC32_INIT_VALUE;

	unsigned char *device;
	unsigned char *brand;
	unsigned char *fbuf;
	int flen;
	struct tpfu_header head;
	fpos_t fzeropos;

	if (fread(&head, sizeof(head), 1, inf) != 1) {
		r = ERR_CRIT_READ;
		FW_FINISH(r, "error reading firmware");
		return r;
	}

	size = ntohl(head.size);
	if (fsize)
		*fsize = size;

	/* mark start of payload */
	fgetpos(inf, &fzeropos);

	if (memcmp(head.magic, TPFU_MAGIC, sizeof(head.magic)) != 0) {
		r = ERR_CRIT_MAGIC;
		FW_FINISH(r, "invalid image magic");
		goto out;
	}
	if (head.major != TPFU_MAJOR || head.minor != TPFU_MINOR) {
		r = ERR_CRIT_VERSION;
		FW_FINISH(r, "invalid image version (%d.%d != %d.%d)", head.major, head.minor, TPFU_MAJOR, TPFU_MINOR);
		goto out;
	}

	if (!scan_config(FW_CONFIG, &brand, &device)) {
		r = ERR_CRIT_CONFIG;
		FW_FINISH(r, "error reading %s", FW_CONFIG);
		goto out;
	}

	if (strncmp(head.device, device, 16) != 0) {
		r = ERR_CRIT_IMAGE;
		FW_FINISH(r, "invalid image for this device");
		goto out;
	}

	fbuf = malloc(16*1024);

	/* calculate SHA1 over fw */
	SHA1Init(&ctx);
	SHA1Update(&ctx, (uint8_t *)&head, sizeof(head));

	sum = 0;
	for (rest = size; rest > 0;) {
		int n;
		int perc = -1;
		int l = min(16 * 1024, rest);

		n = fread(fbuf, 1, l, inf);
		if (n != l)
			break;

		FW_PROGRESS("Calculating SHA1", STEP_SIGN, KB(size), KB(sum), "k");

		sum += n;
		SHA1Update(&ctx, fbuf, n);
		crc32 = fw_crc32(fbuf, n, crc32);
		rest -= n;
	}
	SHA1Final(&ctx, digest);

	if (ntohl(head.crc32) != crc32) {
		r = ERR_CRIT_CRC;
		FW_FINISH(r, "CRC32 mismatch, image: %ud, calculated: %ud", ntohl(head.crc32), crc32);
		goto out;
	}

	FW_PROGRESS("Calculating SHA1", STEP_SIGN, KB(size), KB(size), "k");

	flen = fread(fbuf, 1, 16 * 1024, inf);
	if (flen > 0) {
		switch (check_signature(digest, SHA1_SIZE, fbuf, flen)) {
		case 0:
			break;

		case SIGN_CERT:
			r = ERR_CRIT_CERT_READ;
			FW_FINISH(r, "reading the certificat failed");
			goto out;

		case SIGN_MISMATCH:
			r = ERR_CRIT_SIGN_MATCH;
			FW_FINISH(r, "image does not match signature");
			goto out;

		case SIGN_NOT_AUTH:
			r |= ERR_FLAG_SIGN_AUTH;
			FW_FINISH(r, "authorizing the signature failed");
			break;
		}
	} else {
		r |= ERR_FLAG_NO_SIGN;
		FW_FINISH(r, "image has no signature");
	}

	if (strncmp(head.brand, brand, 16) != 0) {
		r |= ERR_FLAG_BRANDING;
		FW_FINISH(r, "invalid branding for this device");
	}

 out:
	fsetpos(inf, &fzeropos);

	return r;
}
