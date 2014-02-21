--
--    __                        __      _
--   / /__________ __   _____  / /___  (_)___  ____ _
--  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
-- / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
-- \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
--                           /_/            /____/
--
-- (c) Travelping GmbH <info@travelping.com>
--

-- Takes actions, depending on the (dynamic) config's version

local curRev, cfgRev = ...

function warn(format, ...)
	dm.logx("LOG_WARNING", "fncPostVersionCheck: "..string.format(format, ...))
end

if not curRev or not cfgRev then
	dm.logx("LOG_ERR", "fncPostVersionCheck: Invalid parameters")
	return dm.DM_ERROR
end

local rc, results = dm.get{
	{dm.t_string, "InternetGatewayDevice.DeviceInfo.ModelName"}
}
if rc ~= dm.DM_OK then
	warn("Unable to get model name (%d)", rc)
end
local model = results and results[1].value or ""

if cfgRev < curRev then
	dm.logx("LOG_INFO", "fncPostVersionCheck: Upgraded from r"..cfgRev)

	if model == "LNG ONE" then
		if cfgRev < 7380 then
			rc = dm.set{
				{dm.t_string, "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_TPOSS_VAPId", "default"}
			}
			if rc ~= dm.DM_OK then
				warn("Unable to fix virtual access point Id (%d)", rc)
			end
		end

		if cfgRev < 9040 then
			rc = dm.set{
				{dm.t_enum,   "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.Standard", "g"},
				{dm.t_string, "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.RegulatoryDomain", "USI"},
				{dm.t_uint32, "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.X_TPOSS_TxPower", 63} -- hardcoded
			}
			if rc ~= dm.DM_OK then
				warn("Unable to fix WLAN radio settings (%d)", rc)
			end
		end
	end

	if model:match("LNG") then
		if cfgRev < 8340 then -- upgrade from pre-v1.1.0-GA
			rc = dm.set{
				{dm.t_uint32, "InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.TunnelRetryInterval", 15},
				{dm.t_uint32, "InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.SessionRetryInterval", 15},
				{dm.t_uint32, "InternetGatewayDevice.X_TPLINO_NET_NetworkGateway.KeepaliveTimeout", 15}
			}
			if rc ~= dm.DM_OK then
				warn("Unable to fix L2TP timeouts (%d)", rc)
			end
		end

		if cfgRev < 8430 then -- upgrade from pre-v1.1.1-GA
			rc, results = dm.get{
				{dm.t_string, "InternetGatewayDevice.X_TPLINO_NET_SNMP.ReadCommunity"}
			}
			if rc ~= dm.DM_OK then
				warn("Unable to get SNMP read community (%d)", rc)
			end

			rc = dm.set{{
				dm.t_string, "InternetGatewayDevice.X_TPLINO_NET_SNMP.ReadCommunity",
				results[1].value:gsub("@.*$", "", 1)
			}}
			if rc ~= dm.DM_OK then
				warn("Unable to fix SNMP read community (%d)", rc)
			end
		end
	end

	if model:match("SCG") then
		if cfgRev < 8400 then -- upgrade from pre-v2.4.0-GA
			local function convertDER2PEM(file)
				local hnd, err = io.open(file, "rb")
				if not hnd then return warn("%s: %s", file, err) end

				local der = hnd:read("*a")
				hnd:close()
				if not der then return warn("Error while reading %s", file) end

				if der:match("%-%-%-%-%-BEGIN CERTIFICATE%-%-%-%-%-") then
					return warn("%s is already PEM-encoded", file)
				end

				local data
				rc, data = dm.utils_encode_base64(der)
				if rc ~= dm.DM_OK then return warn("Unable to encode %s (%d)", file, rc) end

				hnd, err = io.open(file, "wb")
				if not hnd then return warn("%s: %s", file, err) end

				hnd:write(string.format(
					"-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n",
					data
				))
				hnd:close()
			end

			convertDER2PEM("/jffs/etc/ssl/gateway.ca")
		end
	end
elseif cfgRev > curRev then
	dm.logx("LOG_INFO", "fncPostVersionCheck: Downgraded from r"..cfgRev)
else -- cfgRev == curRev (cannot occur currently)
	dm.logx("LOG_INFO", "fncPostVersionCheck: Config up to date")
end

