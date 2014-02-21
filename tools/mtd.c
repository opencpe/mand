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

#include "ftools.h"
#include "mtd.h"
#include "crc.h"

int mtd_unlock(const char *mtd)
{
	int mtd_fd;
	mtd_info_t mtd_info;
	erase_info_t erase_info;

	/* Open MTD device */
	if ((mtd_fd = mtd_open(mtd, O_RDWR)) < 0) {
		perror(mtd);
		return errno;
	}

	/* Get sector size */
	if (ioctl(mtd_fd, MEMGETINFO, &mtd_info) != 0) {
		perror(mtd);
		close(mtd_fd);
		return errno;
	}

	erase_info.length = mtd_info.size;
	ioctl(mtd_fd, MEMUNLOCK, &erase_info);

	close(mtd_fd);
	return 0;
}

int mtd_erase(const char *mtd)
{
	int mtd_fd;
	mtd_info_t mtd_info;
	erase_info_t erase_info;

	/* Open MTD device */
	if ((mtd_fd = mtd_open(mtd, O_RDWR | O_SYNC)) < 0) {
		perror(mtd);
		return errno;
	}

	/* Get sector size */
	if (ioctl(mtd_fd, MEMGETINFO, &mtd_info) != 0) {
		perror(mtd);
		close(mtd_fd);
		return errno;
	}

	erase_info.length = mtd_info.erasesize;

	for (erase_info.start = 0;
	     erase_info.start < mtd_info.size;
	     erase_info.start += mtd_info.erasesize) {
		ioctl(mtd_fd, MEMUNLOCK, &erase_info);
		if (ioctl(mtd_fd, MEMERASE, &erase_info) != 0) {
			perror(mtd);
			close(mtd_fd);
			return errno;
		}
	}

	close(mtd_fd);
	return 0;
}


int mtd_open(const char *mtd, int flags)
{
	FILE *fp;
	char dev[PATH_MAX];
	int i;

	if ((fp = fopen("/proc/mtd", "r"))) {
		while (fgets(dev, sizeof(dev), fp)) {
			if (sscanf(dev, "mtd%d:", &i) && strstr(dev, mtd)) {
#if defined(WITH_UDEV)
				snprintf(dev, sizeof(dev), "/dev/mtd%d", i);
#else
				snprintf(dev, sizeof(dev), "/dev/mtd/%d", i);
#endif
				fclose(fp);
				return open(dev, flags);
			}
		}
		fclose(fp);
	}

	return open(mtd, flags);
}	

#define check_action()		(fp ? ACT_IDLE : ACT_WEBS_UPGRADE)
#define KB(x) ((x) / 1024)
#define PERCENTAGE(x,total) (((x) * 100) / (total))

int fcrc32(FILE *fp, size_t fsize, unsigned long want_crc)
{
	int sum = 0;
	size_t count, len;
	size_t size = fsize;
	char buf[4096];
 

	unsigned long crc = CRC32_INIT_VALUE;

	FW_PROGRESS("Calculating CRC", STEP_CRC, KB(fsize), 0, "k");

	len = sizeof(buf);
	while (size) {
		if (size < sizeof(buf))
			len = size;

		count = safe_fread(buf, 1, len, fp);
		if (count < len) {
			FW_FINISH(6, "Truncated file (actual %d expect %d)", count, len); 
			return 0;
		}

		/* Update CRC */
		crc = fw_crc32(buf, count, crc);
		size -= count;
		sum += count;
		FW_PROGRESS("Calculating CRC", STEP_CRC, KB(fsize), KB(sum), "k");
	}

	if (crc != want_crc)
		FW_FINISH(6, "bad CRC");

	return crc == want_crc;
}

int flash_erase(int mtd_fd, size_t len, int erasesize)
{
	int failcnt;
	erase_info_t erase;

	erase.start = 0;
	erase.length = len & ~(erasesize - 1);
	if ((len % erasesize))
		erase.length += erasesize;

	/* if the user wants verbose output, erase 1 block at a time and show him/her what's going on */
	int i;
	int blocks = erase.length / erasesize;
	erase.length = erasesize;
	FW_PROGRESS("Erasing blocks", STEP_ERASE, blocks, 0, ""); 
	
	for (i = 1; i <= blocks; i++) {
		FW_PROGRESS("Erasing blocks", STEP_ERASE, blocks, i, ""); 
		for (failcnt = 0;; failcnt++) {
			ioctl(mtd_fd, MEMUNLOCK, &erase);
			if (ioctl(mtd_fd, MEMERASE, &erase) < 0) {
				fprintf(stderr, "erase failed on block 0x%.8x: %m\n", erase.start);

				if (failcnt < 3)
					continue;
				
				FW_FINISH(3, "While erasing blocks 0x%.8x-0x%.8x: %m", 
					  (unsigned int) erase.start, (unsigned int) (erase.start + erase.length)); 
				return 0;
			} else
				break;
		}
		erase.start += erasesize;
	}
	return 1;
}

int fwrite_flash(FILE *fp, size_t fsize, int mtd_fd)
{
	int sum = 0;
	size_t len, count;
	size_t size = fsize;
	char buf[4096];

	/* Write file to MTD device */
	FW_PROGRESS("Writing data", STEP_WRITE, KB(fsize), 0, "k"); 

	len = sizeof(buf);
	while (size) {
		ssize_t result;

		if (size < sizeof(buf))
			len = size;

		FW_PROGRESS("Writing data", STEP_WRITE, KB(fsize), KB(sum), "k"); 

		count = safe_fread(buf, 1, len, fp);
		if (count < len) {
			FW_FINISH(6, "Truncated file (actual %d expect %d)", count, len); 
			return 0;
		}

		/* Do it */
		if ((result = write(mtd_fd, buf, count)) != (int)count) {
			perror("mtd");
			if (result < 0) {
				FW_FINISH(6, "While writing data to 0x%.8x-0x%.8x: %m", 
					  sum, sum + len); 
				return 0;
			}
			FW_FINISH(7, "Short write count returned while writing to x%.8x-0x%.8x: %d/%u bytes written to flash", 
				  sum, sum + len, sum + result, fsize); 
			return 0;
		}
		
		sum += len;
		size -= len;
	}

	FW_PROGRESS("Writing data", STEP_WRITE, KB(fsize), KB(sum), "k"); 
	return 1;
}

