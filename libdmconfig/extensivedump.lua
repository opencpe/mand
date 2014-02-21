--
--    __                        __      _
--   / /__________ __   _____  / /___  (_)___  ____ _
--  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
-- / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
-- \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
--                           /_/            /____/
--
-- (c) Travelping GmbH <info@travelping.com>
--

-- module	:: extensivedump
-- exports	:: retrieve([rootPath], [socketType])

-- workaround to generate a TR deamons database dump including datatypes and enumerations
-- output can be used by DevUIs Click-dummy
-- this information will later be generated during the build process

module(..., package.seeall)

require "luaevent.core"
require "libluadmconfig"

local stringBuffer = {}
local sessionObj

local errHandler, bufferWrite, bufferToString, writeDatabase
local xmlOut = {}

		-- preliminary
function errHandler(rc)
	local errConversion = {
		[dmconfig.r_ok]				= "r_ok",
		[dmconfig.r_err_connection]		= "r_err_connection",
		[dmconfig.r_err_invalid_sessionid]	= "r_err_invalid_sessionid",
		[dmconfig.r_err_requires_cfgsession]	= "r_err_requires_cfgsession",
		[dmconfig.r_err_cannot_open_cfgsession]	= "r_err_cannot_open_cfgsession",
		[dmconfig.r_err_alloc]			= "r_err_alloc",
		[dmconfig.r_err_misc]			= "r_err_misc"
	}
	if rc ~= dmconfig.r_ok then
		print("\aError: "..errConversion[rc])
		if sessionObj then
			sessionObj:terminate()
			sessionObj:shutdown()
		end
		return true
	end
end

function xmlOut.header(indent, encoding)
	bufferWrite(string.rep("\t", indent).."<?xml version='1.0' encoding='"..encoding.."'?>")
end

function xmlOut.beginTag(indent, name, atts)
	local att_name, att_value

	bufferWrite("\n"..string.rep("\t", indent).."<"..name)
	if atts then
		for att_name, att_value in pairs(atts) do
			bufferWrite(" "..att_name..'="'..att_value..'"')
		end
	end
	bufferWrite ">"
end

function xmlOut.endTag(indent, name)
	bufferWrite("\n"..string.rep("\t", indent).."</"..name..">")
end

function xmlOut.endTagText(name)
	bufferWrite("</"..name..">")
end

function bufferWrite(str)
	table.insert(stringBuffer, str)
end

xmlOut.text = bufferWrite

function bufferToString()
	return table.concat(stringBuffer)
end

function writeDatabase(indent, path)
	local rc, nodes, unit

	local typeConversion = {
		[dmconfig.t_bool]	= "boolean",
		[dmconfig.t_uint]	= "unsignedinteger",
		[dmconfig.t_int]	= "integer",
		[dmconfig.t_uint64]	= "unsignedinteger64",
		[dmconfig.t_int64]	= "integer64",
		[dmconfig.t_counter]	= "counter",
		[dmconfig.t_enum]	= "enumeration",
		[dmconfig.t_string]	= "string",
		[dmconfig.t_address]	= "address",
		[dmconfig.t_date]	= "date",
		[dmconfig.t_path]	= "path",
		[dmconfig.t_unknown]	= "unknown"
	}

	rc, nodes = sessionObj:list(path)
	if errHandler(rc) then return true end

	for _, unit in ipairs(nodes) do
		if unit.type == dmconfig.n_object or unit.type == dmconfig.n_table then
			local tag = (unit.type == dmconfig.n_object and "object") or "table"

			xmlOut.beginTag(indent, tag, {name = unit.name})
				if writeDatabase(indent+1, path.."."..unit.name) then return true end
			xmlOut.endTag(indent, tag)
		else -- unit.type == dmconfig.n_parameter
			local rc, results

			rc, results = sessionObj:get{{unit.datatype, path.."."..unit.name}}
			if errHandler(rc) then return true end

			xmlOut.beginTag(indent, "parameter", {name = unit.name, type = typeConversion[unit.datatype]})

			if unit.datatype == dmconfig.t_enum then
				local rc, enums, u

				rc, enums = sessionObj:retrieve_enums(path.."."..unit.name)
				if errHandler(rc) then return true end

				xmlOut.beginTag(indent+1, "enums", {chosen = results[1].value})
				for _, u in ipairs(enums) do
					xmlOut.beginTag(indent+2, "value")
						xmlOut.text(u)
					xmlOut.endTagText("value")
				end
				xmlOut.endTag(indent+1, "enums")
			else
				xmlOut.beginTag(indent+1, "value")
					xmlOut.text(results[1].value)
				xmlOut.endTagText("value")
			end
			xmlOut.endTag(indent, "parameter")
		end
	end
end

		-- only "exported" function

function retrieve(rootPath, socktype)
	local rootPath = rootPath or "InternetGatewayDevice"
	local socktype = socktype or dmconfig.af_unix
	local xml, rc

	local event_base

	if socktype ~= dmconfig.af_unix and socktype ~= dmconfig.af_inet then
		print("Invalid parameter: "..socktype)
		return
	end

	event_base = luaevent.core.new()
	rc, sessionObj = dmconfig.init(event_base, socktype)
	if errHandler(rc) then return end
	if errHandler(sessionObj:start()) then return end

	xmlOut.header(0, "utf-8")
	bufferWrite("\n")

	xmlOut.beginTag(0, "dump", {
		xmlns = "http://www.travelping.net/extensivedump.xsd",
	})
		xmlOut.beginTag(1, "object", {name = string.gsub(rootPath, ".+%.", "")}) 
			if writeDatabase(2, rootPath) then return end
		xmlOut.endTag(1, "object")
	xmlOut.endTag(0, "dump")

	if errHandler(sessionObj:terminate()) then return end
	if errHandler(sessionObj:shutdown()) then return end

	xml = bufferToString()
	stringBuffer = {}

	return xml
end


