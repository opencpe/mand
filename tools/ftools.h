#ifndef _FW_FTOOLS_H
#define _FW_FTOOLS_H

#include <inttypes.h>

#define TPFU_MAGIC      "TPFU"
#define TPFU_MAJOR      2
#define TPFU_MINOR      0

#define FW_CONFIG "/etc/fw_config.sh"

#define KB(x) ((x) / 1024)
#define PERCENTAGE(x,total) (((x) * 100) / (total))

#define STEP_SIGN    1
#define STEP_CRC     2
#define STEP_ERASE   3
#define STEP_WRITE   4

#define ERR_CRIT_ERROR		1
#define ERR_CRIT_READ		2
#define ERR_CRIT_MAGIC		3
#define ERR_CRIT_VERSION	4
#define ERR_CRIT_IMAGE		5
#define ERR_CRIT_CRC		7
#define ERR_CRIT_CERT_READ	8
#define ERR_CRIT_SIGN_MATCH	9
#define ERR_CRIT_CONFIG		10
#define ERR_CRIT_IPKG_UNTAR	11
#define ERR_CRIT_DATA_UNTAR	12

#define ERR_FLAG_MASK           0x00FF
#define ERR_FLAG_BRANDING	0x0100
#define ERR_FLAG_SIGN_AUTH	0x0200
#define ERR_FLAG_NO_SIGN	0x0400


struct __attribute__ ((__packed__)) tpfu_header {
	char magic[4];
	uint8_t major;
	uint8_t minor;
	uint32_t size;
	uint32_t crc32;
	unsigned char brand[16];
	unsigned char device[16];
};

struct __attribute__ ((__packed__)) tpfu_part {
	uint8_t  type;
	uint32_t size;
};

extern struct _fw_callbacks {
	void (*fw_finish)(int code, const char *fmt, ...)
				__attribute__ ((format (printf, 2, 3)));
	void (*fw_progress)(const char *msg, int state, int total, int current,
			    const char *unit);
} fw_callbacks;

#define FW_FINISH(code, fmt, ...) do {					\
	if (fw_callbacks.fw_finish)					\
		fw_callbacks.fw_finish(code, fmt, ##__VA_ARGS__);	\
} while (0)

#define FW_PROGRESS(msg, state, total, current, unit) do {			\
	if (fw_callbacks.fw_progress)						\
		fw_callbacks.fw_progress(msg, state, total, current, unit);	\
} while(0)

#define TPFU_IMAGE      1
#define TPFU_KERNEL     2
#define TPFU_ROOTFS     3

extern int try_kexec;

size_t safe_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t safe_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int validate_tpfu(FILE *inf, int *fsize);

#if defined(WITH_KEXEC)
void sys_kexec_reboot(void);
#else
inline static void sys_kexec_reboot(void) {};
#endif

#endif
