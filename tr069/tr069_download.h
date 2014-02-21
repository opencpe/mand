#ifndef __TR069_DOWNLOAD_H
#define __TR069_DOWNLOAD_H

#include <stdlib.h>

struct download_info {
	char *command_key;
	int  file_type_id;
	char *file_type;
	char *url;
	char *username;
	char *password;
	unsigned int filesize;
	char *filename;
	int delay;
};

static inline void free_download_info(struct download_info *dli)
{
	free(dli->command_key);
	free(dli->file_type);
	free(dli->url);
	free(dli->username);
	free(dli->password);
	free(dli->filename);
	free(dli);
}

extern void *thread_firmware_upgrade(void *arg);
extern void *thread_web_content_download(void *arg);

#endif
