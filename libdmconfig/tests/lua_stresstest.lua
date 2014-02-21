-- Lua stress test

require "libdmconfig"

		-- open read/write session

rc, session = dmconfig.start(dmconfig.s_readwrite)
if rc ~= dmconfig.r_ok then
	print "Couldn't start session"
	print(rc)
	return
end

objectPath = "InternetGatewayDevice.IPPingDiagnostics"

rc, results = session:list(objectPath)
if rc ~= dmconfig.r_ok then
	print '"List" request was unsuccessful'
	return
end

getTable = {}

for _, unit in ipairs(results) do
	if unit.type == dmconfig.n_parameter and unit.datatype ~= dmconfig.t_counter then
		table.insert(getTable, {unit.datatype, objectPath.."."..unit.name})
	end
end

rc, results = session:get(getTable)
if rc ~= dmconfig.r_ok then
	print '"Get" request was unsuccessful'
	return
end

setTable = {}

for i, unit in ipairs(results) do
	table.insert(setTable, {unit.type, getTable[i][2], unit.value})
end

if session:set(setTable) ~= dmconfig.r_ok then
	print '"Set" request was unsuccessful'
	return
end

if session:terminate() ~= dmconfig.r_ok then
	print "Couldn't close session"
	return
end

