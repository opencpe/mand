#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <error.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <string.h>

#include <mtd/mtd-user.h>

#include "mtd.h"
#include "crc.h"
#include "ftools.h"

/* trx header */
#define TRX_MAGIC       0x30524448      /* "HDR0" */
#define TRX_VERSION     1
#define TRX_MAX_LEN     0x3A0000
#define TRX_NO_HEADER   1               /* Do not write TRX header */

#define OFFSETOF(type, member)  ((uint) &((type *)0)->member)

struct trx_header {
        uint32_t magic;                 /* "HDR0" */
        uint32_t len;                   /* Length of file including header */
        uint32_t crc32;                 /* 32-bit CRC from flag_version to end of file */
        uint32_t flag_version;          /* 0:15 flags, 16:31 version */
        uint32_t offsets[3];            /* Offsets of partitions from start of header */
};

int write_firmware(FILE *fp, size_t part_size __attribute__ ((unused)), const char *mtd)
{
	int mtd_fd = -1;
	mtd_info_t mtd_info;
	erase_info_t erase;

	fpos_t fzeropos;
	fpos_t fstartpos;
	struct tpfu_part part;
	struct trx_header trx;

	char buf[1024];
	char *s;
	int ret = -1;
	size_t count;
	unsigned long support_max_len;

	s = nvram_get("flash_type");
	if(s && strstr(s, "640"))		// This is a 8MB flash
		support_max_len = 0x7A0000;	// 8*1024*1024 - 256*1024 - 128*1024;
	else
		support_max_len = TRX_MAX_LEN;

	count = fread(&part, 1, sizeof(part), fp);
	if (count < sizeof(part)) {
		FW_FINISH(1, "File is too small (%d bytes)", count);
		goto fail;
	}

	if (part.type != TPFU_IMAGE) {
		FW_FINISH(2, "invalid image type");
		goto fail;
	}

	/* mark start of payload */
	if (fgetpos(fp, &fzeropos)) {
		perror("fgetpos");
		goto fail;
	}

	/* Examine TRX header */
	count = safe_fread(&trx, 1, sizeof(struct trx_header), fp);
	if (count < sizeof(struct trx_header)) {
		FW_FINISH(1, "File is too small (%d bytes)", count);
		goto fail;
	}

	switch(trx.magic) {
		case 0x47343557: /* W54G */
		case 0x53343557: /* W54S */
		case 0x73343557: /* W54s */
		case 0x46343557: /* W54F */
		case 0x55343557: /* W54U */
			/* ignore the first 32 bytes */
			count = safe_fread(&trx, 1, 32 - sizeof(struct trx_header), fp);

			/* mark start of payload */
			if (fgetpos(fp, &fzeropos)) {
				perror("fgetpos");
				goto fail;
			}

			count = safe_fread(&trx, 1, sizeof(struct trx_header), fp);
			if (count < sizeof(struct trx_header)) {
			        FW_FINISH(1, "File is too small (%d bytes)", count);
				goto fail;
			}
			break;
	}

	if (trx.magic != TRX_MAGIC ||
	    trx.len > support_max_len ||
	    trx.len < sizeof(struct trx_header)) {
		FW_FINISH(2, "Bad trx header");
		goto fail;
	}

	/* Open MTD device and get sector size */
	if ((mtd_fd = mtd_open(mtd, O_RDWR)) < 0 ||
	    ioctl(mtd_fd, MEMGETINFO, &mtd_info) != 0 ||
	    mtd_info.erasesize < sizeof(struct trx_header)) {
		perror(mtd);
		goto fail;
	}

	/* do in mtd_info.erasesize chunks */
	erase.length = mtd_info.erasesize;

	if (trx.flag_version & TRX_NO_HEADER)
		trx.len -= sizeof(struct trx_header);

	if (!flash_erase(mtd_fd, trx.len, mtd_info.erasesize))
		goto fail;

	/* Reset fp to payload start */ 
	if (!(trx.flag_version & TRX_NO_HEADER))
		fsetpos(fp, &fzeropos);
	else
		fsetpos(fp, &fstartpos);

	/* Write file to MTD device */
	if (fwrite_flash(fp, trx.len, mtd_fd)) {
		ret = 0;
		FW_FINISH(0, "success");
	}

 fail:
	/* Dummy read to ensure chip(s) are out of lock/suspend state */
	(void) read(mtd_fd, buf, 2);

	if (mtd_fd >= 0)
		close(mtd_fd);

	return ret;
}

#if defined(WITH_KEXEC)
void sys_kexec_reboot()
{
}
#endif
