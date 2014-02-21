-- libdmconfig client lib sample: uses the nonblocking libevent-based API
-- only to be used on device manager test builds (where writing the firmware is disabled)

require "libluadmconfig"
require "luaevent.core"

local rc, session

local FIRMWARE = "/home/rhaberkorn/working_copy/embedded/tplino/trunk/dm_clean/libdmconfig/tests/firmware.tplino"

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

	rc, startev = session:start(nil, nil, dmconfig.s_configure, function(event, session, _, rc)
		if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
			print "Couldn't start session"
			return
		end
		print "Session started successfully"

		rc, subev, fwupdateev = session:fwupdate(FIRMWARE, "linux", 0,
			function(event, session, _, code, msg) -- finish callback
				if event ~= dmconfig.d_answer_ready then
					print "Error while receiving a finish callback"
					return
				end

				print(string.format("FINISH CB: %s (%d)", msg, code))

				if code == -1 then
					print "Last finish callback received - cleaning up..."

					rc, termev = session:terminate(function(event, _, _, rc)
						if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
							print "Couldn't terminate session"
							return
						end
						print "Session terminated successfully"
					end)
					if rc ~= dmconfig.r_ok then
						print "Couldn't register terminate session callback"
						return
					end
					print "Terminate session callback registered"
				end
			end, nil,
			function(event, session, _, msg, state, current, total, unit) -- progress callback
				if event ~= dmconfig.d_answer_ready then
					print "Error while receiving a progress callback"
					return
				end

				io.write(string.format("\rPROGRESS CB (%u): %s: %d%s/%d%s (%d%%)", state, msg, current, unit, total, unit, (current*100)/total))
				if current == total then print "" end
			end, nil,
			function(event, session, _, rc)
				if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
					print "Couldn't start firmware update process"
					return
				end
				print "Firmware update process started"
			end
		)
		if rc ~= dmconfig.r_ok then
			print "Couldn't register firmware update callback"
			return
		end
		print "Firmware update callback registered"
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

