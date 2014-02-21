#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <mtd/mtd-user.h>

#include "mtd.h"
#include "ftools.h"

#define MACLEN	17
#define CONF_PART "boardconfig"
#define TMP_FILE  "/tmp/board.bin"

#define OFF_MACS 0x60L

static void fw_finish(int code, const char *fmt, ...)
{
	va_list ap;
	
	va_start(ap, fmt);

	fprintf(stderr, "\nflash result: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, " (%d)\n", code);
	
	va_end(ap);
}

static void fw_progress(const char *msg, int state, int total, int current, const char *unit)
{

	fprintf(stderr, "\r%s: %d%s/%u%s (%d%%)",
			msg, current, unit, total, unit, PERCENTAGE(current, total));
			if (current == total)
				fprintf(stderr, "\n");
}

struct _fw_callbacks fw_callbacks = {
	.fw_finish = fw_finish,
	.fw_progress = fw_progress
};

const char *valer = "Error: Failed to verify %s MAC\n";

inline void printmac(const unsigned char *mac)
{
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", *mac, mac[1], mac[2], mac[3], mac[4], mac[5]);
}

inline void usage(void)
{
	puts("\nflshathmac V0.1\n\n\
This tool needs exactly two arguments.\n\
Syntax: flshathmac [WLAN-MAC] [WAN-MAC]\n");
}

int readmac(const char *arg, unsigned char *buf)
{
	int c, p = 0;

	if (strlen(arg) != MACLEN)
		return 0;
	for (c = 0; c < MACLEN; c++) {
		if (!((c + 1) % 3)) {
			switch (arg[c]) {
				case ':':
				case '-':
					break;
				default:
					return 0;
			}
		} else {
			if (!(p % 2))
				buf[p / 2] = 0;
			switch (arg[c]) {
				case 'a' ... 'f':
					buf[p / 2] += arg[c] - 0x57;
					break;
				case 'A' ... 'F':
					buf[p / 2] += arg[c] - 0x37;
					break;
				case '0' ... '9':
					buf[p / 2] += arg[c] - 0x30;
					break;
				default:
					return 0;
			}
			if (!(p % 2))
				buf[p / 2] <<= 4;
			p++;
		}
	}

	return 1;
}

int processimage(const unsigned char *newmacs)
{
	FILE *img;
	unsigned char macbuf[12];
	int ret = 0;

	if ((img = fopen(TMP_FILE, "r+")) == NULL)
		return ret;

	if ((fseek(img, OFF_MACS, SEEK_SET)) != 0)
		goto fail;

	if (fread(macbuf, 2, 6, img) != 6)
		goto fail;

	printf("WLAN MAC was ");
	printmac(macbuf);
	printf("WAN  MAC was ");
	printmac(macbuf+6);

	if ((fseek(img, OFF_MACS, SEEK_SET)) != 0)
		goto fail;

	if (fwrite(newmacs, 2, 6, img) != 6)
		goto fail;

	ret = 1;

fail:
	fclose(img);
	return ret;
}

int getimage(void)
{
	FILE *img;
	mtd_info_t mtd_info;
	int mtd_fd, ret = 0;
	size_t len, count, btsrd, trnsfrd = 0;
	char buf[0x1000];

	len = sizeof(buf);

	if ((img = fopen(TMP_FILE, "w")) == NULL)
		return ret;
	
	if ((mtd_fd = mtd_open(CONF_PART, O_RDONLY)) < 0)
		goto fail1;
	
	if (ioctl(mtd_fd, MEMGETINFO, &mtd_info) != 0)
		goto fail2;

	while (trnsfrd < mtd_info.size) {
		if ((btsrd = read(mtd_fd, buf, len)) <= 0)
			goto fail2;
		if ((count = safe_fwrite(buf, 1, btsrd, img)) != btsrd)
			goto fail2;
		trnsfrd += count;
	}

	ret = 1;
	
fail2:
	close(mtd_fd);
fail1:
	fclose(img);
	return ret;
}

int writeimgback(void)
{
	FILE *img;
	mtd_info_t mtd_info;
	int mtd_fd, ret = 0;

	if ((img = fopen(TMP_FILE, "r")) == NULL)
		return ret;

	if ((mtd_fd = mtd_open(CONF_PART, O_RDWR)) < 0)
		goto fail1;

	if (ioctl(mtd_fd, MEMGETINFO, &mtd_info) != 0 || mtd_info.erasesize < 0x1000)
		goto fail2;

	if (!flash_erase(mtd_fd, mtd_info.size, mtd_info.erasesize))
		goto fail2;

	if (!fwrite_flash(img, mtd_info.size, mtd_fd))
		goto fail2;

	ret = 1;

fail2:
	close(mtd_fd);
fail1:
	fclose(img);
	unlink(TMP_FILE);
	return ret;
}

int main(int argc, char *argv[])
{
	unsigned char macs[12];

	if (argc != 3) {
		usage();
		return -1;
	}
	if (!readmac(argv[1], macs)) {
		fprintf(stderr, valer, "WLAN");
		return -1;
	}
	if (!readmac(argv[2], macs + 6)) {
		fprintf(stderr, valer, "WAN");
		return -1;
	}
	if (!getimage())  {
		fprintf(stderr, "Error: Unable to access board configuration.\n");
		return -1;
	}
	
	if (!processimage(macs)) {
		fprintf(stderr, "Error: Unable to process flash image!\n");
		return -1;
	}
	if (!writeimgback()) {
		fprintf(stderr, "Error: Something horrible happend during flashing!\n\
If you power off the Device now, it will be broken!\n");
	}

	return 0;
}
