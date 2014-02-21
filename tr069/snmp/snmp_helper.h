#ifndef __SNMP_HELPER_H
#define __SNMP_HELPER_H

static unsigned long long ltime(void)
{
        struct timeval tv;

        gettimeofday(&tv, NULL);
        return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

#endif
