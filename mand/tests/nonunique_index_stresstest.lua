require "libluadmconfig"
require "luaevent.core"

		-- open configure session

evctx = luaevent.core.new()
rc, session = dmconfig.init(evctx)
if rc ~= dmconfig.r_ok then
	error("Couldn't initiate session object or establish a connection to the server")
end

print "Initiating the session object was successful"

if session:start(nil, 20, dmconfig.s_readwrite) ~= dmconfig.r_ok then
	error("Couldn't start session")
end

print "Session started successfully."

local CNATIPS = 20
local INSLIMIT = 5
local NATIPs = {}

math.randomseed(1)

for i = 1, CNATIPS do
	table.insert(NATIPs, {
		IP = string.format("%d.%d.%d.%d", math.random(1,254), math.random(0,254), math.random(0,254), math.random(1,254)),
		inst = {}
	})
	print(NATIPs[#NATIPs].IP)
end
print "----"

local path = "InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone"

rc, instance = session:add(path)
if rc ~= dmconfig.r_ok then error("add zone") end

path = path.."."..instance..".Clients.Client"

for i = 1, 1000 do
	local nat = NATIPs[math.random(1,#NATIPs)]

	if #nat.inst == INSLIMIT then
		for i = 1, math.random(1, INSLIMIT) do
			local ind = math.random(1, #nat.inst)
			
			print("DEL", nat.inst[ind], nat.IP)
			rc = session:delete(path.."."..nat.inst[ind])
			if rc ~= dmconfig.r_ok then error("remove client") end

			table.remove(nat.inst, ind)
			print("INST", unpack(nat.inst))
		end
	else
		rc, instance = session:add(path)
		if rc ~= dmconfig.r_ok then error("add client") end

		print("ADD", instance, nat.IP)
		rc = session:set{
			{dmconfig.t_address, path.."."..instance..".NATIPAddress", nat.IP}
		}
		if rc ~= dmconfig.r_ok then error("set client nat ip") end

		if next(nat.inst) then
			table.insert(nat.inst, 2, instance)
		else
			table.insert(nat.inst, instance)
		end
		print("INST", unpack(nat.inst))
	end
end

if session:terminate() ~= dmconfig.r_ok then
	error("Couldn't close session")
end

print "Session closed successfully"

if session:shutdown() ~= dmconfig.r_ok then
	error("Couldn't shutdown the server connection")
end

print "Shutting down the server connection was successful"

