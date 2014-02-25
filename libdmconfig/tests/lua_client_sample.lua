-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

-- Lua sample program to test the Lua libdmconfig interface

require "libluadmconfig"
require "luaevent.core"

function abort(...)
	print(...)
	if session then
		session:terminate()
		session:shutdown()
	end
end

		-- open configure session

evctx = luaevent.core.new()
rc, session = dmconfig.init(evctx)
if rc ~= dmconfig.r_ok then
	abort("Couldn't initiate session object or establish a connection to the server")
	return
end

print "Initiating the session object was successful"

if session:start(nil, 20, dmconfig.s_configure) ~= dmconfig.r_ok then
	abort("Couldn't start session")
	return
end

print "Session started successfully."

		-- set some parameters

if session:set{
	{dmconfig.t_unknown,	"InternetGatewayDevice.ManagementServer.PeriodicInformInterval", "42"},
	{dmconfig.t_string,	"InternetGatewayDevice.DeviceInfo.ModelName", "Blabla TEST"},
	{dmconfig.t_enum,	"InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.UseAllocatedWAN", "UseAllocatedSubnet"},
} ~= dmconfig.r_ok then
	abort('"Set" request was unsuccessful')
	return
end



--[[dum = string.rep("X", 1*8*1024)
print(session:set {
	{dmconfig.t_unknown, "InternetGatewayDevice.DeviceInfo.ModelName", dum}
})]]

print '"Set" request was successful'

if session:commit() ~= dmconfig.r_ok then
	abort('"Commit" was unsuccessful')
	return
end

print '"Commit" was successful'

--[[
if session:save_config("192.168.2.27") ~= dmconfig.r_ok then
	abort('"Saveconfig" was unsuccessful')
	return
end

print '"Saveconfig" was successful'

if session:restore_config("192.168.2.27") ~= dmconfig.r_ok then
	abort('"Restoreconfig" was unsuccessful')
	return
end

print '"Restoreconfig" was successful'
]]
		-- switch session to read/write mode
                -- just for demonstration purposes

if session:switch() ~= dmconfig.r_ok then
	abort('"Switch session" was unsuccessful')
	return
end

print '"Switch session" was successful'

		-- retrieve some parameters

rc, results = session:get{
	{dmconfig.t_date,	"InternetGatewayDevice.DeviceInfo.FirstUseDate"},
	{dmconfig.t_int,	"InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPLeaseTime"},
	{dmconfig.t_string,	"InternetGatewayDevice.DeviceInfo.ModelName"},
	{dmconfig.t_address,	"InternetGatewayDevice.DeviceInfo.SyslogServer"},
	{dmconfig.t_unknown,	"InternetGatewayDevice.DeviceInfo.Manufacturer"}
}
if rc ~= dmconfig.r_ok then
	abort('"Get" request was unsuccessful')
	return
end

print '"Get" request was successful'

for _, unit in ipairs(results) do
	print("Received "..(
		(unit.type == dmconfig.t_int or unit.type == dmconfig.t_uint) and "integer" or
		unit.type == dmconfig.t_string and "string" or
		unit.type == dmconfig.t_address and "address" or
		unit.type == dmconfig.t_bool and "boolean" or
		unit.type == dmconfig.t_date and "time and date")..": "..unit.value)
end

		-- switch session back to read/write mode

if session:switch(nil, 20, dmconfig.s_configure) ~= dmconfig.r_ok then
	abort('"Switch session" was unsuccessful')
	return
end

print '"Switch session" was successful'

		-- add an object instance and delete it afterwards

rc, instance = session:add("InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType")
if rc ~= dmconfig.r_ok then
	abort('"Add instance" request was unsuccessful')
	return
end

print '"Add instance" request was successful'
path = "InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType."..instance
print("New instance: "..path)

if session:delete(path) ~= dmconfig.r_ok then
	abort('"Delete instance" request was unsuccessful')
	return
end

print '"Delete instance" request was successful'
print("Deleted instance: "..path)

rc, instance = session:find("InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType", "Name", dmconfig.t_string, "br")
if rc ~= dmconfig.r_ok then
	abort('"Find instance" request was unsuccessful')
	return
end

print '"Find instance" request was successful'
print("Found instance: InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType."..instance)

		-- some other commands/requests

rc, dump = session:dump()
if rc ~= dmconfig.r_ok then
	abort('"Dump" request was unsuccessful')
	return
end

print '"Dump" request was successful'
print "Received data:"
print(dump)

rc, nodes = session:list("InternetGatewayDevice")
if rc ~= dmconfig.r_ok then
	abort('"List" request was unsuccessful')
	return
end

print '"List" request was successful'
print 'Retrieved nodes (in "InternetGatewayDevice"):'
for _, unit in ipairs(nodes) do
	if unit.type == dmconfig.n_object then
		print("Object("..unit.size.."): "..unit.name)
	elseif unit.type == dmconfig.n_parameter then
		print("Parameter(type:"..unit.datatype.."): "..unit.name)
	elseif unit.type == dmconfig.n_table then
		print("Table: "..unit.name)
	else
		abort("An error occurred: Invalid node type retrieved")
		return
	end
end

		-- t_enumid GET/SET tests

rc, enumvals = session:retrieve_enums("InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.UseAllocatedWAN")
if rc ~= dmconfig.r_ok then
	abort('"Retrieve enums" request was unsuccessful')
	return
end

print '"Retrieve enums" request was successful'

rc, results = session:get{
	{dmconfig.t_enumid, "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.UseAllocatedWAN"}
}
if rc ~= dmconfig.r_ok then
	abort('"Get" request was unsuccessful')
	return
end

print '"Get" request was successful'

print("UseAllocatedWAN = "..results[1].value..' = "'..enumvals[results[1].value+1]..'"')

rc, results = session:get{
	{dmconfig.t_unknown, "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.UseAllocatedWAN"}
}
if rc ~= dmconfig.r_ok then
	abort('"Get" request was unsuccessful')
	return
end

print '"Get" request was successful'

print("Received enum string: "..results[1].value)

rc, results = session:get_session_info()
if rc ~= dmconfig.r_ok then
	abort('"Get session info" request was unsuccessful')
	return
end

print '"Get session info" request was successful'

print("Received session flags: ", unpack(results))

		-- close session

if session:terminate() ~= dmconfig.r_ok then
	abort("Couldn't close session")
	return
end

print "Session closed successfully"

if session:shutdown() ~= dmconfig.r_ok then
	abort("Couldn't shutdown the server connection")
	return
end

print "Shutting down the server connection was successful"

