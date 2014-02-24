require "libluadmconfig"
require "luaevent.core"

evctx = luaevent.core.new()
rc, session = dmconfig.init(evctx)
if rc ~= dmconfig.r_ok then
	error("Couldn't initiate session object or establish a connection to the server")
end


if session:start(0, nil, dmconfig.s_readwrite) ~= dmconfig.r_ok then
	error("Couldn't start session")
end

local path = "InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone"

rc, instance = session:add(path)
if rc ~= dmconfig.r_ok then error("add zone") end

path = path.."."..instance..".Clients.Client"

rc, instance = session:add(path, 32769)
-- 0.0.0.0: 32769
rc, instance = session:add(path, 32772)
-- 0.0.0.0: 32769, 32772
rc, instance = session:add(path, 32773)
-- 0.0.0.0: 32769, 32773, 32772
rc, instance = session:add(path, 32774)
-- 0.0.0.0: 32769, 32774, 32773, 32772
rc = session:set{
	{dmconfig.t_address, path..".32774.NATIPAddress", "2.0.0.0"},
-- 0.0.0.0: 32769, 32773, 32772
-- 2.0.0.0: 32774
	{dmconfig.t_address, path..".32773.NATIPAddress", "1.0.0.0"},
-- 0.0.0.0: 32769, 32772
-- 1.0.0.0: 32773
-- 2.0.0.0: 32774
	{dmconfig.t_address, path..".32769.NATIPAddress", "2.0.0.0"}
-- 0.0.0.0: 32772
-- 1.0.0.0: 32773
-- 2.0.0.0: 32774, 32769
}
rc = session:delete(path..".32773")
-- 0.0.0.0: 32772
-- 2.0.0.0: 32774, 32769
rc = session:delete(path..".32774")
-- 0.0.0.0: 32772
-- 2.0.0.0: 32769
rc = session:delete(path..".32769")
-- 0.0.0.0: 32772

session:terminate()
session:shutdown()
