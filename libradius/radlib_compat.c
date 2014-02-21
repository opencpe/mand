#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

void srandomdev()
{
	int fd, done;

	done = 0;
	fd = open("/dev/urandom", O_RDONLY, 0);
	if (fd >= 0) {
		unsigned int seed;

		if (read(fd, &seed, sizeof(seed)) == (ssize_t) sizeof(seed))
			done = 1;
		close(fd);
		srandom(seed);
	}

	if (!done) {
		struct timeval tv;
		unsigned long junk;

		gettimeofday(&tv, NULL);
		srandom((getpid() << 16) ^ tv.tv_sec ^ tv.tv_usec ^ junk);
		return;
	}
}

