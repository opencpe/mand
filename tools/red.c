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
#include <unistd.h>

#include <mtd/mtd-user.h>

#include "mtd.h"
#include "crc.h"
#include "ftools.h"

#define P_KERNEL "kernel"
#define P_ROOTFS "rootfs"
#define GPIO_LED "/sys/devices/platform/leds-gpio/leds/gpio0/trigger"

int
write_firmware(FILE *fp, size_t part_size __attribute__ ((unused)),
	       const char *mtd __attribute__ ((unused)))
{
	const char *heart = "heartbeat";
	int ret = -1;
	int mtd_fd = -1;
	int led_fd;

	if ((led_fd = open(GPIO_LED, O_RDWR)) > 0) {
		write(led_fd, heart, 9);
		close(led_fd);
	}

	enum {
		S_ROOTFS = 1,
		S_KERNEL
	} step;

	for (step = S_KERNEL; step; step--) {
		mtd_info_t mtd_info;
		struct tpfu_part part;

		size_t count = fread(&part, 1, sizeof(part), fp);
		if (count < sizeof(part)) {
			FW_FINISH(1, "File is too small (%d bytes)", count);
			goto fail;
		}

		switch (step) {
		case S_KERNEL:
			switch (part.type) {
			case TPFU_ROOTFS:
				FW_FINISH(2, "found rootfs before kernel image");
				goto fail;
			case TPFU_KERNEL:
				break;
			default:
				FW_FINISH(2, "invalid image type");
				goto fail;
			}

			if ((mtd_fd = mtd_open(P_KERNEL, O_RDWR)) < 0) {
				FW_FINISH(2, "could not find/open mtd device");
				goto fail;
			}

			break;

		case S_ROOTFS:
			if (part.type != TPFU_ROOTFS) {
				FW_FINISH(2, "invalid image type");
				goto fail;
			}

			if ((mtd_fd = mtd_open(P_ROOTFS, O_RDWR)) < 0) {
				FW_FINISH(2, "could not find/open mtd device");
				goto fail;
			}

			break;
		}

		/* get sector size */
		if (ioctl(mtd_fd, MEMGETINFO, &mtd_info) != 0 ||
		    mtd_info.erasesize < 0x1000) { //actual size should be 0x00010000
			    			   //this is just to ensure there is some reasonable erase size
			FW_FINISH(2, "invalid mtd erasesize");
			goto fail;
		}

		if (!flash_erase(mtd_fd, part.size, mtd_info.erasesize))
			goto fail;

		if (!fwrite_flash(fp, part.size, mtd_fd))
			goto fail;
	}

	FW_FINISH(0, "success");
	ret = 0;

fail:

	if (mtd_fd >= 0) {
		char buf[2];

		/* Dummy read to ensure chip(s) are out of lock/suspend state */
		read(mtd_fd, buf, 2);
		close(mtd_fd);
	}

	return ret;
}

#if defined(WITH_KEXEC)
void sys_kexec_reboot()
{
}
#endif
