#ifndef _FW_MTD_H
#define _FW_MTD_H

#define FLAG_VERBOSE	0x01
#define FLAG_JS		0x02
#define FLAG_FORCE	0x04
#define FLAG_NO_SIGN	0x08

int mtd_open(const char *mtd, int flags);
int mtd_erase(const char *mtd);
int mtd_unlock(const char *mtd);

int fcrc32(FILE *fp, size_t fsize, unsigned long want_crc);
int flash_erase(int mtd_fd, size_t len, int erasesize);
int fwrite_flash(FILE *fp, size_t fsize, int mtd_fd);

int write_firmware(FILE *fp, size_t size, const char *mtd);

#endif /* _FW_MTD_H */
