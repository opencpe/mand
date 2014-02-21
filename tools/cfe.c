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

#include <linux/mtd/mtd.h>

#include "mtd.h"
#include "crc.h"
#include "ftools.h"
#include "tr069/bcm63xx_board.h"

#define BCM_SIG_1   "Broadcom Corporation"
#define BCM_SIG_2   "ver. 2.0"          // was "firmware version 2.0" now it is split 6 char out for chip id.

#define BCM_TAG_VER         "6"
#define BCM_TAG_VER_LAST    "26"

// file tag (head) structure all is in clear text except validationTokens (crc, md5, sha1,etc). Total: 128 unsigned chars
#define TAG_LEN         256
#define TAG_VER_LEN     4
#define SIG_LEN         20
#define SIG_LEN_2       14   // Original second SIG = 20 is now devided into 14 for SIG_LEN_2 and 6 for CHIP_ID
#define CHIP_ID_LEN             6
#define IMAGE_LEN       10
#define ADDRESS_LEN     12
#define FLAG_LEN        2
#define TOKEN_LEN       20
#define BOARD_ID_LEN    16
#define RESERVED_LEN    (TAG_LEN - TAG_VER_LEN - SIG_LEN - SIG_LEN_2 - CHIP_ID_LEN - BOARD_ID_LEN - \
                        (4*IMAGE_LEN) - (3*ADDRESS_LEN) - (3*FLAG_LEN) - (2*TOKEN_LEN))

#define OFFSETOF(type, member)  ((uint) &((type *)0)->member)

// TAG for downloadable image (kernel plus file system)
struct bcm_image_tag
{
    unsigned char tagVersion[TAG_VER_LEN];       // tag version.  Will be 2 here.
    unsigned char signiture_1[SIG_LEN];          // text line for company info
    unsigned char signiture_2[SIG_LEN_2];        // additional info (can be version number)
    unsigned char chipId[CHIP_ID_LEN];                   // chip id
    unsigned char boardId[BOARD_ID_LEN];         // board id
    unsigned char bigEndian[FLAG_LEN];           // if = 1 - big, = 0 - little endia of the host
    unsigned char totalImageLen[IMAGE_LEN];      // the sum of all the following length
    unsigned char cfeAddress[ADDRESS_LEN];       // if non zero, cfe starting address
    unsigned char cfeLen[IMAGE_LEN];             // if non zero, cfe size in clear ASCII text.
    unsigned char rootfsAddress[ADDRESS_LEN];    // if non zero, filesystem starting address
    unsigned char rootfsLen[IMAGE_LEN];          // if non zero, filesystem size in clear ASCII text.
    unsigned char kernelAddress[ADDRESS_LEN];    // if non zero, kernel starting address
    unsigned char kernelLen[IMAGE_LEN];          // if non zero, kernel size in clear ASCII text.
    unsigned char dualImage[FLAG_LEN];           // if 1, dual image
    unsigned char inactiveLen[FLAG_LEN];         // if 1, the image is INACTIVE; if 0, active
    unsigned char reserved[RESERVED_LEN];        // reserved for later use
    unsigned char imageValidationToken[TOKEN_LEN];// image validation token - can be crc, md5, sha;  for
                                                 // now will be 4 unsigned char crc
    unsigned char tagValidationToken[TOKEN_LEN]; // validation token for tag(from signiture_1 to end of imageValidationToken)
} __attribute__ ((__packed__));

#define KB(x) ((x) / 1024)
#define PERCENTAGE(x,total) (((x) * 100) / (total))

#if defined (WITH_BCM63XX)

int bcm63xx_get_id(char *buf, size_t size)
{
	int fd;
	BOARD_IOCTL_PARMS IoctlParms = {
		.string = buf,
		.strLen = size,
		.offset = 0,
		.action = 0,
	};

	fd = open("/dev/bcrmboard", O_RDWR);
	if (fd < 0) {
		FW_FINISH(1, "Failed to open board: %m");
		return 0;
	}

	if (ioctl(fd, BOARD_IOCTL_GET_ID, &IoctlParms) < 0) {
		perror("ioctl");
		FW_FINISH(2, "ioctl failed: %m");
		close(fd);
		return 0;
	}
	close(fd);
	return 1;
}

int bcm63xx_flash(unsigned int offset, uint8_t *data, size_t size)
{
	int fd;
	BOARD_IOCTL_PARMS IoctlParms = {
		.string = data,
		.strLen = size,
		.offset = offset,
		.action = BCM_IMAGE_FS,
	};

	fd = open("/dev/bcrmboard", O_RDWR);
	if (fd < 0) {
		FW_FINISH(1, "Failed to open board: %m");
		return 0;
	}

	if (ioctl(fd, BOARD_IOCTL_FLASH_WRITE, &IoctlParms) < 0) {
		perror("ioctl");
		FW_FINISH(2, "ioctl failed: %m");
		close(fd);
		return 0;
	}
	close(fd);
	return 1;
}
#endif

int write_firmware(FILE *fp, size_t part_size, const char *mtd)
{
	int mtd_fd = -1;
	mtd_info_t mtd_info;

	fpos_t fzeropos;
	struct tpfu_part part;
	struct bcm_image_tag itag;
	struct bcm_image_tag ftag;
	uint32_t crc;

	char buf[1024];
	size_t count;
	int len;
	int ret = -1;

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

	/* Examine header */
	count = safe_fread(&itag, 1, sizeof(itag), fp);
	if (count < sizeof(itag)) {
		FW_FINISH(1, "File is too small (%d bytes)", count);
		goto fail;
	}

	if (strlen(itag.tagVersion) != strlen(BCM_TAG_VER) ||
	    strcmp(itag.tagVersion, BCM_TAG_VER) != 0) {
		FW_FINISH(2, "Wrong  image file version (%s != %s)", itag.tagVersion, BCM_TAG_VER);
		goto fail;
	}

	len = strtol(itag.cfeLen, NULL, 10);
	if (len) {
		FW_FINISH(4, "Image with CFE is not supported");
		goto fail;
	}

	crc = fw_crc32((uint8_t *) &itag,
		    OFFSETOF(struct bcm_image_tag, tagValidationToken),
		    CRC32_INIT_VALUE);

	if (crc != *(uint32_t *)&itag.tagValidationToken) {
		FW_FINISH(5, "invalid header CRC");
		goto fail;
	}

	len = strtol(itag.totalImageLen, NULL, 10);

	if (!fcrc32(fp, len, *(uint32_t *)&itag.imageValidationToken))
		goto fail;

	fsetpos(fp, &fzeropos);

#if 0
#if defined (WITH_BCM63XX)
#endif
	char board_id[BOARD_ID_LEN];

	if (!bcm63xx_get_id(board_id, sizeof(board_id)))
		goto fail;

	if (strncmp(board_id, itag.boardId, sizeof(board_id)) != 0) {
		fprintf(stderr, "Image type mismatch\n");
		goto fail;
	}

	unsigned int offs;
	uint8_t *fw_buf;

	len = strtol(itag.totalImageLen, NULL, 10);
	len += sizeof(itag);

	fw_buf = malloc(len);
	if (!fw_buf) {
		FW_FINISH(3, "Out of memory");
		goto fail;
	}

	count = safe_fread(fw_buf, 1, len, fp);
	if (count != len) {
		FW_FINISH(4, "Short read, (%d != %d)", len, count);
		goto fail;
	}

	offs = strtoll(itag.rootfsAddress, NULL, 10);
	if (!offs) {
		FW_FINISH(4, "Image error");
		goto fail;
	}
	offs -= sizeof(itag);

	bcm63xx_flash(offs, fw_buf, len);

 fail:
	return 1;
#else
	/* Open MTD device and get sector size */
	if ((mtd_fd = mtd_open(mtd, O_RDWR)) < 0 ||
	    ioctl(mtd_fd, MEMGETINFO, &mtd_info) != 0 ||
	    mtd_info.erasesize < sizeof(itag)) {
		perror(mtd);
		goto fail;
	}

	len = strtol(itag.totalImageLen, NULL, 10) + sizeof(itag);
	if (mtd_info.size < len) {
		FW_FINISH(4, "Image too big");
		goto fail;
	}

	if (read(mtd_fd, &ftag, sizeof(ftag)) != sizeof(ftag)) {
		FW_FINISH(3, "Failed to read image tag from flash");
		goto fail;
	}
	lseek(mtd_fd, 0, SEEK_SET);

	if (strncmp(ftag.chipId,    itag.chipId,    sizeof(ftag.chipId))    != 0 ||
	    strncmp(ftag.boardId,   itag.boardId,   sizeof(ftag.boardId))   != 0 ||
	    strncmp(ftag.bigEndian, itag.bigEndian, sizeof(ftag.bigEndian)) != 0) {
		fprintf(stderr, "Image type mismatch\n");
		goto fail;
	}

	if (!flash_erase(mtd_fd, len, mtd_info.erasesize))
		goto fail;

	if (fwrite_flash(fp, len, mtd_fd)) {
		ret = 0;
		FW_FINISH(0, "success");
	}

 fail:
	if (buf) {
		/* Dummy read to ensure chip(s) are out of lock/suspend state */
		(void) read(mtd_fd, buf, 2);
		free(buf);
	}

	if (mtd_fd >= 0)
		close(mtd_fd);
#endif

	return ret;
}

#if defined(WITH_KEXEC)
void sys_kexec_reboot()
{
}
#endif
