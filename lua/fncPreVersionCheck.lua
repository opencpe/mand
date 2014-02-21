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

if not curRev or not cfgRev then
	dm.logx("LOG_ERR", "fncPreVersionCheck: Invalid parameters")
	return dm.DM_ERROR
end

if cfgRev < curRev then
	dm.logx("LOG_INFO", "fncPreVersionCheck: Upgraded from r"..cfgRev)

	if cfgRev < 6000 then
			-- config bases on base config values which are now in the default config
		dm.deserialize_directory("/etc/defaults/dm")
		dm.deserialize_directory("/jffs/etc/defaults/dm")

			-- HTTP servers/APIs were always enabled
		dm.deserialize_file("/usr/share/tr069d/httpservers.xml")
	end

	if cfgRev < 8340 then -- pre v1.1.0-GA
		os.execute("cp /etc/defaults/ssl/dmcacert.crt /jffs/etc/ssl")
	end
elseif cfgRev > curRev then
	dm.logx("LOG_INFO", "fncPreVersionCheck: Downgraded from r"..cfgRev)
else -- cfgRev == curRev (cannot occur currently)
	dm.logx("LOG_INFO", "fncPreVersionCheck: Config up to date")
end

