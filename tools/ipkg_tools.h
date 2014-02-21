#ifndef __IPKG_H
#define __IPKG_H

#define IPKG_INSTALL_ROOT "/jffs"
#define IPKG_PLIST_DIR IPKG_INSTALL_ROOT "/etc/ipkg"

int install_ipkg(const char *fname, int verbose);
int remove_ipkg(const char *pkg_name, int verbose);

#endif
