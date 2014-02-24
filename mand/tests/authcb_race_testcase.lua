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

	rc, startev = session:start(nil, 30, dmconfig.s_readwrite, function(event, session, _, rc)
		if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
			print "Couldn't start session"
			return
		end
		print "Session started successfully"

		local path = "InternetGatewayDevice.X_TPLINO_NET_SessionControl.Zone.32769.Clients.Client.49153"

		rc, reqev = session:gw_req_client_accessclass(path, "foo", "bar", "Online",
			function(event, _, _, rc, authReqState, authResult, replyCode, messages)
				print(string.format("gw_req_client_accessclass: event=%d, rc=%d", event, rc))

				if rc == dmconfig.r_ok then
					print(string.format("gw_req_client_accessclass: authReqState=%d, authResult=%d, replyCode=%d", authReqState, authResult, replyCode))
					print(unpack(messages or {}))
				end
			end)
		if rc ~= dmconfig.r_ok then
			print "Couldn't register gw_req_client_accessclass callback"
			return
		end
		print "gw_req_client_accessclass callback registered"

		rc, delev = session:delete(path, function(event, _, _, rc)
			if event ~= dmconfig.d_answer_ready or rc ~= dmconfig.r_ok then
				print "Couldn't delete instance"
				return
			end
			print "Instance deleted successfully"

			print("Deleted instance: "..path)
		end)
		if rc ~= dmconfig.r_ok then
			print "Couldn't register delete instance callback"
			return
		end
		print "Delete instance callback registered"
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

