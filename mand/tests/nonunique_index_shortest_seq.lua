--
-- searches randomly for the shortest sequence of data base operations involving
-- non-unique indexes that gets tr069d to crash.
--

require "libluadmconfig"
require "luaevent.core"

math.randomseed(os.time())

local bestseq = {} -- shortest sequences
local bestlen = 20 -- shortest sequences' length

local ippool = {} -- IP pool

print "IP POOL"
for _ = 1, 10 do
	table.insert(ippool, string.format("%d.%d.%d.%d", math.random(1,254), math.random(0,254), math.random(0,254), math.random(1,254)))
	print(ippool[#ippool])
end
print "----"

while true do

os.execute("./tr069d -f 2>/dev/null 1>/dev/null &")
--os.execute("sleep 1") -- libdmconfig has to start up

evctx = luaevent.core.new()

rc = dmconfig.r_err_connection
while rc == dmconfig.r_err_connection do
	rc, session = dmconfig.init(evctx)
end
if rc ~= dmconfig.r_ok then
	error("Couldn't initiate session object or establish a connection to the server")
end


if session:start(nil, 20, dmconfig.s_readwrite) ~= dmconfig.r_ok then
	error("Couldn't start session")
end

local path = "InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone"

rc, instance = session:add(path)
if rc ~= dmconfig.r_ok then error("add zone") end

path = path.."."..instance..".Clients.Client"

local seq = {} -- current sequence
local instances = {} -- currently used instances

-- generate sequence
while true do
	local cmd = math.random(1, 3)

	rc = dmconfig.r_ok

	if cmd == 1 then -- create instance
		rc, instance = session:add(path)
		if rc ~= dmconfig.r_ok then error("add client") end

		table.insert(instances, instance)
		
		table.insert(seq, {"ADD", instance})
	elseif cmd == 2 then -- set NATIP
		if next(instances) then
			instance = instances[math.random(1, #instances)]
			local ip = ippool[math.random(1, #ippool)]
			
			table.insert(seq, {"SET", instance, ip})

			rc = session:set{
				{dmconfig.t_address, path.."."..instance..".NATIPAddress", ip}
			}
			--if rc ~= dmconfig.r_ok then error("set client nat ip") end
		end
	elseif cmd == 3 then -- delete instance
		if next(instances) then
			instance = table.remove(instances, math.random(1, #instances))
			
			table.insert(seq, {"DEL", instance})

			rc = session:delete(path.."."..instance)
			--if rc ~= dmconfig.r_ok then error("remove client") end
		end
	end

	if #seq > bestlen then -- sequence cannot beat best sequence
		break
	end
	-- #seq <= bestlen

	if rc ~= dmconfig.r_ok then -- assume tr069d crashed
		if #seq < bestlen then
			bestseq = {}
			bestlen = #seq
		end -- else #seq == bestlen
		table.insert(bestseq, seq)

		print(string.format("BEST SEQUENCES (LENGTH=%d)", bestlen))

		for i, s in ipairs(bestseq) do
			io.write(i..": ")
			for _, e in ipairs(s) do
				if e[1] == "ADD" then io.write(string.format("ADD -> %d; ", e[2]))
				elseif e[1] == "SET" then io.write(string.format("SET %d=%s; ", e[2], e[3]))
				elseif e[1] == "DEL" then io.write(string.format("DEL %d; ", e[2]))
				end
			end
			print "FIN"
		end
		print "----"
		
		break
	end
end

-- start new sequence. old seq got too long or DM crashed

os.execute("pkill tr069d")

end
