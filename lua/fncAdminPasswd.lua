-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

-- Set "admin" user's password by processing passwd

local args = {...}
local rc

local file = "/jffs/etc/passwd"

local function logErr(str)
	dm.logx("LOG_ERR", "fncAdminPasswd: "..str)
	return dm.DM_ERROR
end

local pwd = args[1]
if not pwd then
	local results

	rc, results = dm.get{
		{dm.t_string, "InternetGatewayDevice.LANConfigSecurity.ConfigPassword"}
	}
	if rc ~= dm.DM_OK then return rc end

	pwd = results[1].value
end

local encrypted = ""
if #pwd > 0 then
	rc, encrypted = dm.crypt(pwd, "$1$XqKq7qD9$")
	if rc ~= dm.DM_OK then return rc end
end

local f, msg = io.open(file, "r")
if not f then return logErr(msg) end

local data = {}
for line in f:lines() do
	table.insert(data, (line:gsub("^(admin:).-:", "%1"..encrypted..":")))
end

f:close()

f, msg = io.open(file, "w+")
if not f then return logErr(msg) end

f:write(table.concat(data, "\n"))
f:write "\n"

f:close()

