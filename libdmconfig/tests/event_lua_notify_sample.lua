-- libdmconfig client lib sample: uses the nonblocking libevent-based API

require "libluadmconfig"
require "luaevent.core"

local rc, session

local SHUTDOWN_PARAM = "InternetGatewayDevice.DeviceInfo.ModelName"

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

	rc, startev = session:start(0, nil, dmconfig.s_readwrite, function(event, session, _, rc)
		if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
			print "Couldn't start session"
			return
		end
		print "Session started successfully"

		rc, subev, notifyev = session:subscribe(function(event, session, _, events)
			if event ~= dmconfig.d_answer_ready then
				print "Couldn't retrieve active notification"
				return
			end

			local unit
			for _, unit in ipairs(events) do
				if unit.type == dmconfig.e_changed then
					print('Notification: Parameter "'..unit.info.path..'" changed to "'..unit.info.value..'".')

					if unit.info.path == SHUTDOWN_PARAM then
						rc, subsubev = session:unsubscribe(function(event, session, _, rc)
							if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
								print "Couldn't unsubscribe notifications"
								return
							end
							print "Notifications unsubscribed successfully"

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
						end)
						if rc ~= dmconfig.r_ok then
							print "Couldn't register notification unsubscription callback"
							return
						end
						print "Notification unsubscription callback registered"
					end
				else
					print "Notification: Warning, unknown type"
				end
			end
		end, nil, function(event, session, _, rc)
			if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
				print "Couldn't subscribe notifications"
				return
			end
			print "Notifications subscribed successfully"

			rc, addev = session:recursive_param_notify(true, "", function(event, _, _, rc)
				if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
					print "Couldn't add parameter notifications"
					return
				end
				print "Parameter notifications added successfully"
				print ""
				print("The sample program shuts down when the following parameter is modified: "..SHUTDOWN_PARAM)
				print ""
			end)
			if rc ~= dmconfig.r_ok then
				print "Couldn't register add parameter notification callback"
				return
			end
			print "Add parameter notification callback registered"
		end)
		if rc ~= dmconfig.r_ok then
			print "Couldn't register notification subscription callback"
			return
		end
		print "Notification subscription callback registered"
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

