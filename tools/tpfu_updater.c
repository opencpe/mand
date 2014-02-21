#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/mount.h>
#include "ftools.h"

#define FIRMWARE_DEVICE "/dev/sda1"
#define IMG_PATH "/rom"

static int copy_to(char *fname, FILE *inf, int size)
{
	FILE *outf;
	char *buf;

	buf = malloc(4096);
	if (!buf) {
		FW_FINISH(1, "out of memory");
		return 1;
	}

	outf = fopen(fname, "w");
	if (!outf) {
		perror("creating file");
		return 1;
	}

	while (size > 0) {
		int r, len;

		len = size;
		if (len > 4096)
			len = 4096;

		r = fread(buf, 1, len, inf);
		if (r != len) {
			FW_FINISH(2, "short read by %d byte, corrupted image", r);
			break;
		}
		r = fwrite(buf, 1, len, outf);
		if (r != len) {
			FW_FINISH(3, "short write by %d byte", r);
			break;
		}
		size -= len;
	}
	fclose(outf);

	free(buf);
	return (size != 0);
}

static int rename_from_temp(char *fname)
{
	int r;
	char *toname, *s;

	if (!fname)
		return 0;
	toname = strdup(fname);
	s = strrchr(toname, '.');
	if (!s)
		return 1;
	*s = '\0';
	r = rename(fname, toname);
	free(toname);
	free(fname);
	return r;
}

static int unlink_temp(char *fname)
{
	int r;

	if (!fname)
		return 0;
	r = unlink(fname);
	free(fname);
	return r;
}

int write_firmware(FILE *inf, int size, const char *fname, int step)
{
	struct tpfu_part part;

	int len;
	int ret = 1;
	char *rootfs = NULL;
	char *kernel = NULL;

	if (mount(FIRMWARE_DEVICE, IMG_PATH, "msdos", 0, NULL) != 0) {
		FW_FINISH(4, "unable to mount " IMG_PATH ": %m");
		return 1;
	}

	while (size > 0) {
		char *fname = NULL;

		if (fread(&part, sizeof(part), 1, inf) != 1) {
			FW_FINISH(4, "reading part header: %m");
			goto out_unlink;
		}
		size -= sizeof(part);

		switch (part.type) {
			case TPFU_KERNEL:
				if (kernel) {
					FW_FINISH(4, "duplicate kernel part");
					goto out_unlink;
				}
				fname = kernel = strdup(IMG_PATH "/vmlinuz.XXXXXX");
				break;
			case TPFU_ROOTFS:
				if (rootfs) {
					FW_FINISH(5, "duplicate rootfs part");
					goto out_unlink;
				}
				fname = rootfs = strdup(IMG_PATH "/rootfs.XXXXXX");
				break;
			default:
				FW_FINISH(6, "unknown part");
				goto out_unlink;
		}

		if (copy_to(fname, inf, ntohl(part.size))) {
			goto out_unlink;
		}
		size -= ntohl(part.size);
	}

	if (size != 0) {
		FW_FINISH(7, "short read by %d byte, corrupted image", size);
		goto out_unlink;
	}

	ret = rename_from_temp(kernel);
	ret |= rename_from_temp(rootfs);

	if (ret == 0)
		FW_FINISH(0, "success");

 out_umount:
	umount(IMG_PATH);
	return ret;

 out_unlink:
	unlink_temp(kernel);
	unlink_temp(rootfs);

	umount(IMG_PATH);
	return 1;
}

#if defined(WITH_KEXEC)
void sys_kexec_reboot()
{
	int rc;

	if (mount(FIRMWARE_DEVICE, IMG_PATH, "msdos", MS_RDONLY, NULL) != 0) {
		FW_FINISH(4, "unable to mount " IMG_PATH ": %m");
		return;
	}

	rc = system("kexec -l " IMG_PATH "/vmlinuz --initrd=" IMG_PATH "/rootfs --reuse-cmdline");
	umount(IMG_PATH);

	if (WEXITSTATUS(rc) == 0)
		system("kexec -e");
}

#endif
