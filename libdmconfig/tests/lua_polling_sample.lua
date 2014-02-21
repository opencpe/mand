-- Lua sample program to demonstrate event polling in a read-only session

require "libluadmconfig"
require "luaevent.core"

function sleep(delay)
	local start = os.time()
	while os.time() < start+delay do end
end

evctx = luaevent.core.new()
rc, session = dmconfig.init(evctx)
if rc ~= dmconfig.r_ok then
	print "Couldn't initiate socket"
	return
end
print "Socket initialisation successful"

if session:start(0) ~= dmconfig.r_ok then
	print "Couldn't start session"
	return
end
print '"Start session" was successful'

if session:subscribe() ~= dmconfig.r_ok then
	print "Couldn't subscribe for notifications"
	return
end
print "Subscribed notifications"

if session:recursive_param_notify(false, "") ~= dmconfig.r_ok then
	print "Couldn't add notifications"
	return
end
print "Notifications added"

io.write "Polling. Terminate Lua by pressing CTRL-C (the session stays open)"
io.flush()

while true do
	rc, events = session:get_passive_notifications()
	if rc == dmconfig.r_err_invalid_sessionid then
		print "\nNotification: Session timed out. Returning..."
		return
	elseif rc ~= dmconfig.r_ok then
		print "\nAn error occurred: Couldn't poll"
		return
	end -- rc == dmconfig.r_ok

	for _, unit in ipairs(events) do
		if unit.type == dmconfig.e_changed then
			print('\nNotification: Parameter "'..unit.info.path..'" changed to "'..unit.info.value..'".')
		else
			print "\nNotification: Warning, unknown event"
		end
	end

	io.write "."
	io.flush()
	sleep(1)
end

if session:unsubscribe() ~= dmconfig.r_ok then
	print "Couldn't unsubscribe notifications"
	return
end
print '"Unsubscribe notifications" was successful'

if session:terminate() ~= dmconfig.r_ok then
	print "Couldn't close session"
	return
end
print '"Terminate" was successful'

if session:shutdown() ~= dmconfig.r_ok then
	print "Couldn't shut down socket"
	return
end
print "Shutting down the socket was successful"

