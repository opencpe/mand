/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) 2004-2006 Andreas Schultz <aschultz@warp10.net>
 * (c) 2007 Travelping GmbH <info@travelping.com>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>

#include <adsldrv.h>

#include "tr069_token.h"
#include "tr069_store.h"

#define SDEBUG
#include "debug.h"

#define ADSL_MIB_INV_SERIAL_NUMBER       "00000000000000000000000000000001"
#define ADSL_MIB_INV_VERSION_NUMBER      "Broadcom DSL Version "
#define ADSL_MIB_VENDOR_ID_G_DMT         "B500BDCM0000"
#define ADSL_MIB_VENDOR_ID_T1_413        "544D"

static int adsl_fd = -1;

static int get_adsl(void)
{
	if (adsl_fd != -1) {
		/* test if the fd is still alive */
		struct pollfd pfd = {
			.fd = adsl_fd,
			.events = POLLIN | POLLOUT
		};
		int r;

		r = poll(&pfd,  1, 0);
		debug("(): poll result: %d, errno: %d, revents: %x", r, errno, pfd.revents);
		if ((r == -1 && errno == EBADF) ||
		    pfd.revents & (POLLERR | POLLHUP | POLLNVAL) != 0) {
			close(adsl_fd);
			adsl_fd = -1;
		}
	}

	if (adsl_fd == -1)
		if ((adsl_fd = open("/dev/bcmadsl0", O_RDWR)) == -1)
			perror("open bcmadsl0");

	return adsl_fd;
}

static BCMADSL_STATUS get_value(char *id, int idlen, void *buf, size_t *buflen)
{
	int fd;

	if ((fd = get_adsl()) != -1) {
		ADSLDRV_GET_OBJ obj = {
			.bvStatus = BCMADSL_STATUS_ERROR,
			.objId       = id,
			.objIdLen    = idlen,
			.dataBuf     = buf,
			.dataBufLen  = *buflen,
		};

                if (ioctl(fd, ADSLIOCTL_GET_OBJ_VALUE, &obj) == 0) {
			*buflen = obj.dataBufLen;

			return obj.bvStatus;
		}
        }
	return BCMADSL_STATUS_ERROR;
}

static BCMADSL_STATUS get_version(adslVersionInfo *ver)
{
	int fd;

	if ((fd = get_adsl()) != -1) {
		ADSLDRV_GET_VERSION obj = {
			.bvStatus = BCMADSL_STATUS_ERROR,
			.pAdslVer  = ver,
		};

		if (ioctl(fd, ADSLIOCTL_GET_VERSION, obj) == 0)
			return obj.bvStatus;
        }
	return BCMADSL_STATUS_ERROR;
}

static BCMADSL_STATUS start_connection(void)
{
	int fd;

	if ((fd = get_adsl()) != -1) {
		ADSLDRV_STATUS_ONLY obj = {
			.bvStatus = BCMADSL_STATUS_ERROR,
		};

		if (ioctl(fd, ADSLIOCTL_CONNECTION_START, obj) == 0)
			return obj.bvStatus;
        }
	return BCMADSL_STATUS_ERROR;
}

static BCMADSL_STATUS stop_connection(void)
{
	int fd;

	if ((fd = get_adsl()) != -1) {
		ADSLDRV_STATUS_ONLY obj = {
			.bvStatus = BCMADSL_STATUS_ERROR,
		};

		if (ioctl(fd, ADSLIOCTL_CONNECTION_STOP, obj) == 0)
			return obj.bvStatus;
        }
	return BCMADSL_STATUS_ERROR;
}

static BCMADSL_STATUS get_connection_info(ADSLDRV_CONNECTION_INFO *info)
{
	int fd;

	if ((fd = get_adsl()) != -1) {
		info->bvStatus = BCMADSL_STATUS_ERROR;

		if (ioctl(fd, ADSLIOCTL_GET_CONNECTION_INFO, info) == 0)
			return info->bvStatus;
        }
	return BCMADSL_STATUS_ERROR;
}

static int link_state_map[] = {
	[BCM_ADSL_LINK_UP]                         = 0,     /* Up */
	[BCM_ADSL_LINK_DOWN]                       = 3,     /* NoSignal */
	[BCM_ADSL_TRAINING_G992_EXCHANGE]          = 2,     /* EstablishingLink */
        [BCM_ADSL_TRAINING_G992_CHANNEL_ANALYSIS]  = 2,     /* EstablishingLink */
        [BCM_ADSL_TRAINING_G992_STARTED]           = 2,     /* EstablishingLink */
        [BCM_ADSL_TRAINING_G994]                   = 2,     /* EstablishingLink */
        [BCM_ADSL_G994_NONSTDINFO_RECEIVED]        = 4,     /* Error */
	[BCM_ADSL_BERT_COMPLETE]                   = 3,     /* NoSignal */
        [BCM_ADSL_ATM_IDLE]                        = 0,     /* Up */
	[BCM_ADSL_EVENT]                           = 4,     /* Error */
	[BCM_ADSL_G997_FRAME_RECEIVED]             = 4,     /* Error */
	[BCM_ADSL_G997_FRAME_SENT]                 = 4,     /* Error */
};

static int modulation_type_map[] = {
	[kAdslModGdmt]    =  0,     /* ADSL_G.dmt */
	[kAdslModT1413]   =  6,     /* ADSL_ANSI_T1.413 */
	[kAdslModGlite]   =  1,     /* ADSL_G.lite */
	[kAdslModAnnexI]  =  7,     /* G.shdsl ?????????????????????????????????????? */
	[kAdslModAdsl2]   =  2,     /* ADSL_G.dmt.bis */
	[kAdslModAdsl2p]  =  4,     /* ADSL_2plus */
	[kAdslModReAdsl2] =  3,     /* ADSL_re-adsl */
	/* =  5,     * ADLS_four */
	/* =  8,     * IDSL */
	/* =  9,     * HDSL */
	/* = 10,     * SDSL */
	/* = 11,     * VDSL */
};

static int line_coding_map[] = {
	[kAdslLineCodingOther] = 6,
	[kAdslLineCodingDMT]   = 0,     /* DMT */
	[kAdslLineCodingCAP]   = 1,     /* CAP */
	[kAdslLineCodingQAM]   = 5,     /* QAM */
	/* 2,     * B1Q */
	/* 3,     * 3BT */
	/* 4,     * PAM */
};

#define DSLCfgAlias(x) \
	DM_VALUE x(tr069_id, const struct tr069_element *, DM_VALUE) __attribute__ ((alias ("get_IGD_WANDev_i_WANDSLInterfaceConfig")))

DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_Status);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_ModulationType);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_LineEncoding);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_DataPath);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_InterleaveDepth);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_LineNumber);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_UpstreamCurrRate);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_DownstreamCurrRate);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_UpstreamMaxRate);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_DownstreamMaxRate);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_UpstreamNoiseMargin);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_DownstreamNoiseMargin);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_UpstreamAttenuation);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_DownstreamAttenuation);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_UpstreamPower);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_DownstreamPower);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_ATURVendor);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_ATURCountry);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_ATURANSIStd);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_ATURANSIRev);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_ATUCVendor);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_ATUCCountry);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_ATUCANSIStd);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_ATUCANSIRev);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_TotalStart);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_ShowtimeStart);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_LastShowtimeStart);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_CurrentDayStart);
DSLCfgAlias(get_IGD_WANDev_i_DSLCfg_QuarterHourStart);

DM_VALUE get_IGD_WANDev_i_WANDSLInterfaceConfig(tr069_id id,
						const struct tr069_element *elem,
						DM_VALUE val)
{
	static char buf[32];

	ADSLDRV_CONNECTION_INFO info;
	adslMibInfo data;
	size_t size = sizeof(data);
	adslChanEntry *chan_data;

	debug("(%d, %p)", id, elem);

	get_value(NULL, 0, &data, &size);

	switch (id) {
	case cwmp__IGD_WANDev_i_DSLCfg_Status:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.Status */

		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.Enable */
		if (!tr069_get_bool_by_selector((tr069_selector){ cwmp__InternetGatewayDevice,
						cwmp__IGD_WANDevice,
						1,
						cwmp__IGD_WANDev_i_WANDSLInterfaceConfig,
						cwmp__IGD_WANDev_i_DSLCfg_Enable, 0 }))
			val.v.uint_val = 5; /* Disabled */
		else {
			get_connection_info(&info);
			val.v.uint_val = link_state_map[info.ConnectionInfo.LinkState];
		}
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_ModulationType:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.ModulationType */
		debug("(): ModulationType: %d", data.adslConnection.modType);
		val.v.uint_val = modulation_type_map[data.adslConnection.modType];
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_LineEncoding:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.LineCoding */
		debug("(): LineEncoding: %d", data.adslLine.adslLineCoding);
		val.v.uint_val = line_coding_map[data.adslLine.adslLineCoding];
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_DataPath:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.DataPath */
		debug("(): DataPath: %d", data.adslConnection.chType);
		if (data.adslConnection.chType == kAdslIntlChannel)
			val.v.uint_val = 0;     /* Interleaved */
		else if (data.adslConnection.chType == kAdslFastChannel)
			val.v.uint_val = 1;     /* Fast */
		else
			val.v.uint_val = 2;     /* Error */
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_InterleaveDepth:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.InterleaveDepth */
		val.v.uint_val = 0;
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_LineNumber:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.LineNumber */
		val.v.uint_val = 1;
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_UpstreamCurrRate:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.UpstreamCurrRate */
		get_connection_info(&info);
		if (data.adslConnection.chType == kAdslIntlChannel)
			val.v.uint_val = info.ConnectionInfo.ulInterleavedUpStreamRate;
		else
			val.v.uint_val = info.ConnectionInfo.ulFastUpStreamRate;
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_DownstreamCurrRate:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.DownstreamCurrRate */
		get_connection_info(&info);
		if (data.adslConnection.chType == kAdslIntlChannel)
			val.v.uint_val = info.ConnectionInfo.ulInterleavedDnStreamRate;
		else
			val.v.uint_val = info.ConnectionInfo.ulFastDnStreamRate;
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_UpstreamMaxRate:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.UpstreamMaxRate */
		debug("(): DataPath: %ld", data.adslPhys.adslCurrAttainableRate);
		val.v.uint_val = data.adslPhys.adslCurrAttainableRate;
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_DownstreamMaxRate:
		/** VAR: (tdb) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.DownstreamMaxRate */
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_UpstreamNoiseMargin:
		/** VAR: (tdb) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.UpstreamNoiseMargin */
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_DownstreamNoiseMargin:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.DownstreamNoiseMargin */
		debug("(): DownstreamNoiseMargin: %d", data.adslPhys.adslCurrSnrMgn);
		val.v.uint_val = data.adslPhys.adslCurrSnrMgn;
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_UpstreamAttenuation:
		/** VAR: (tdb) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.UpstreamAttenuation */
		debug("(): SignalAttn: %ld", data.adslPhys.adslSignalAttn);
		debug("(): HlinScaleFactor: %ld", data.adslPhys.adslHlinScaleFactor);
		debug("(): LDCompleted: %ld", data.adslPhys.adslLDCompleted);

		break;

	case cwmp__IGD_WANDev_i_DSLCfg_DownstreamAttenuation:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.DownstreamAttenuation */
		debug("(): DownstreamAttenuation: %ld", data.adslPhys.adslCurrAtn);
		val.v.uint_val = data.adslPhys.adslCurrAtn;
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_UpstreamPower:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.UpstreamPower */
		debug("(): CurrOutputPwr: %ld", data.adslPhys.adslCurrOutputPwr);
		val.v.uint_val = data.adslPhys.adslCurrOutputPwr;
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_DownstreamPower:
		/** VAR: (tbd) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.DownstreamPower */
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_ATURVendor:
		/** VAR: InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.ATURVendor */
		switch (data.adslConnection.modType) {
		case kAdslModGdmt:
			strncpy(buf, ADSL_MIB_VENDOR_ID_G_DMT, sizeof(buf));
			break;

		case kAdslModT1413:
			strncpy(buf, ADSL_MIB_VENDOR_ID_T1_413, sizeof(buf));
			break;

		case kAdslModGlite:
		default:
			strncpy(buf, "", sizeof(buf));
		}
		val.v.string = buf;
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_ATURCountry:
		/** VAR: (tbd) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.ATURCountry */
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_ATURANSIStd:
		/** VAR: (tbd) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.ATURANSIStd */
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_ATURANSIRev:
		/** VAR: (tbd) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.ATURANSIRev */
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_ATUCVendor:
		/** VAR: (tbd) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.ATUCVendor */
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_ATUCCountry:
		/** VAR: (tbd) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.ATUCCountry */
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_ATUCANSIStd:
		/** VAR: (tbd) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.ATUCANSIStd */
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_ATUCANSIRev:
		/** VAR: (tbd) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.ATUCANSIRev */
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_TotalStart:
		/** VAR: (tbd) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.TotalStart */
		break;

	case cwmp__IGD_WANDev_i_DSLCfg_ShowtimeStart:
		/** VAR: (tbd) InternetGatewayDevice.WANDevice.{i}.WANDSLInterfaceConfig.ShowtimeStart */
		break;
	}

	return val;
}
