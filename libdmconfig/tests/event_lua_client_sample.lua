-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

-- libdmconfig client lib sample: uses the nonblocking libevent-based API

require "libluadmconfig"
require "luaevent.core"

local rc, session, sid, newctx

evctx = luaevent.core.new()
rc, session = dmconfig.init_events(evctx)
if rc ~= dmconfig.r_ok then
	print "Couldn't initiate session object."
	return
end
print "Session object created"

rc, connev = session:connect(function(event, session)
	local rc

	if event ~= dmconfig.d_connected then
		print "Couldn't connect socket"
		return
	end
	print "Socket connected successfully"

	rc, startev = session:start(nil, 10, dmconfig.s_configure, function(event, session, _, rc)
		if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
			print "Couldn't start session"
			return
		end
		print "Session started successfully"

		rc, setev = session:set({
			{dmconfig.t_unknown,	"InternetGatewayDevice.ManagementServer.PeriodicInformInterval", "42"},
			{dmconfig.t_string,	"InternetGatewayDevice.DeviceInfo.ModelName", "Blabla TEST"}
		}, function(event, session, _, rc)
			if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
				print "Couldn't set parameters"
				return
			end
			print "Parameters set successfully"

			rc, commitev = session:commit(function(event, _, _, rc)
				if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
					print "Couldn't commit changes"
					return
				end
				print "Changes committed successfully"
			end)
			if rc ~= dmconfig.r_ok then
				print "Couldn't register commit callback"
				return
			end
		end)
		if rc ~= dmconfig.r_ok then
			print "Couldn't register set parameter callback"
			return
		end
		print "Set parameter callback registered"

		rc, getev = session:get({
			{dmconfig.t_date,	"InternetGatewayDevice.DeviceInfo.FirstUseDate"},
			{dmconfig.t_int,	"InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPLeaseTime"},
			{dmconfig.t_address,	"InternetGatewayDevice.DeviceInfo.SyslogServer"},
			{dmconfig.t_unknown,	"InternetGatewayDevice.DeviceInfo.Manufacturer"}
		}, function(event, _, _, rc, results)
			if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
				print "Couldn't retrieve parameters"
				return
			end
			print "Parameters retrieved successfully"

			local unit
			for _, unit in ipairs(results) do
				print("Received "..(
					(unit.type == dmconfig.t_int or unit.type == dmconfig.t_uint) and "integer" or
					unit.type == dmconfig.t_string and "string" or
					unit.type == dmconfig.t_address and "address" or
					unit.type == dmconfig.t_bool and "boolean" or
					unit.type == dmconfig.t_date and "time and date")..": "..unit.value)
			end
		end)
		if rc ~= dmconfig.r_ok then
			print "Couldn't register get parameter callback"
			return
		end
		print "Get parameter callback registered"

		rc, addev = session:add("InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType", function(event, session, _, rc, instance)
			if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
				print "Couldn't add instance"
				return
			end
			print "Instance added successfully"

			local path = "InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType."..instance
			print("New instance: "..path)

			rc, delev = session:delete(path, function(event, _, path, rc)
				if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
					print "Couldn't delete instance"
					return
				end
				print "Instance deleted successfully"

				print("Deleted instance: "..path)
			end, path)
			if rc ~= dmconfig.r_ok then
				print "Couldn't register delete instance callback"
				return
			end
			print "Delete instance callback registered"
		end)
		if rc ~= dmconfig.r_ok then
			print "Couldn't register add instance callback"
			return
		end
		print "Add instance callback registered"

		rc, findev = session:find("InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType",
					  "Name", dmconfig.t_string, "br", function(event, _, _, rc, instance)
			if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
				print "Couldn't find instance"
				return
			end

			print("Instance found: InternetGatewayDevice.X_TPOSS_InterfaceMap.InterfaceType."..instance)
		end)
		if rc ~= dmconfig.r_ok then
			print "Couldn't register find instance callback"
			return
		end
		print "Find instance callback registered"

		rc, dumpev = session:dump(function(event, _, _, rc, data)
			if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
				print "Couldn't dump database"
				return
			end
			print "Database dumped successfully"

			print "Received data:"
			print(data)
		end)
		if rc ~= dmconfig.r_ok then
			print "Couldn't register dump callback"
			return
		end
		print "Dump callback registered"

		local path = "InternetGatewayDevice"
		rc, listev = session:list(path, function(event, _, path, rc, nodes)
			if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
				print "Couldn't list object"
				return
			end
			print "Object listed successfully"

			print('Retrieved nodes (in "'..path..'"):')
			local unit
			for _, unit in ipairs(nodes) do
				if unit.type == dmconfig.n_object then
					print("Object("..unit.size.."): "..unit.name)
				elseif unit.type == dmconfig.n_parameter then
					print("Parameter(type:"..unit.datatype.."): "..unit.name)
				elseif unit.type == dmconfig.n_table then
					print("Table: "..unit.name)
				end
			end
		end, path)
		if rc ~= dmconfig.r_ok then
			print "Couldn't register list callback"
			return
		end
		print "List callback registered"
	end)
	if rc ~= dmconfig.r_ok then
		print "Couldn't register start session callback"
		return
	end
	print "Start session callback registered"
end)
if rc ~= dmconfig.r_ok then
	print "Couldn't register connect callback"
	return
end
print "Connect callback registered"

evctx:loop()

session:shutdown()

rc, newctx = dmconfig.init(evctx)
if rc ~= dmconfig.r_ok then
	print "Couldn't initiate new session object."
	return
end
print "New session object created"

_, sid = session:get_sessionid()
newctx:set_sessionid(sid)

if newctx:terminate() ~= dmconfig.r_ok then
	print "Couldn't terminate session"
	return
end
print "Session terminated successfully"

newctx:shutdown()

