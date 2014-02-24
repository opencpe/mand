#include <stdio.h>
#include <stdlib.h>

const char *get_if_device(void *sel)
{
	return "eth0";
}

int nvram_commit(void)
{
	return 0;
}

char * nvram_get(const char *name)
{
	return NULL;
}

int nvram_set(const char *name, const char *value)
{
	return 0;
}

int nvram_unset(const char *name)
{
	return 0;
}

int sys_shutdown_system(unsigned long magic)
{
	return 0;
}

int wget(char *url, FILE *output)
{
	return -1;
}

int mtd_write(FILE *fp, const char *mtd, int flags)
{
	return -1;
}

struct soapResult_t *doBootstrap()
{
}

//get_IGD__i_HotSpotEnabled
