AM_CFLAGS = -D_GNU_SOURCE -g

sbin_PROGRAMS = fwupdate ipkg
# noinst_PROGRAMS = fw_sfx_dummy fw_sfx

noinst_LTLIBRARIES = libmtd.la

libmtd_la_SOURCES = crc.c ftools.c routers.c ipkg_tools.c
libmtd_la_LIBADD = $(NVRAMLIBS)

if FW_TRX
libmtd_la_SOURCES += trx.c mtd.c
endif

if FW_CFE
libmtd_la_SOURCES += cfe.c mtd.c
endif

if FW_TPFU
libmtd_la_SOURCES += tpfu_updater.c
endif

if FW_RED
libmtd_la_SOURCES += red.c mtd.c
noinst_PROGRAMS = flshathmac
flshathmac_SOURCES = flshathmac.c
flshathmac_LDADD = libmtd.la
endif

if BRCM43XX
libmtd_la_SOURCES += brcm43xx.c
endif

ipkg_SOURCES = ipkg.c
ipkg_LDADD = libmtd.la

fwupdate_SOURCES = fw_update.c reboot.c
fwupdate_LDADD = libmtd.la

fw_sfx_SOURCES = fw_update_sfx.c reboot.c
fw_sfx_LDADD = -lnvram
fw_sfx_LDFLAGS = -static

fw_sfx_dummy_SOURCES = fw_update_sfx.c reboot.c
fw_sfx_dummy_LDADD = libmtd.la
fw_sfx_dummy_LDFLAGS = -static

fw_sfx: fw_sfx_dummy $(srcdir)/fw_update_sfx.c reboot.o libmtd.la
	$(LINK) -DSFX_OFFS=$(shell stat -c"%s" fw_sfx_dummy) $(srcdir)/fw_update_sfx.c reboot.o libmtd.la
