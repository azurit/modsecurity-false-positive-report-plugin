-- -----------------------------------------------------------------------
-- OWASP CRS Plugin
-- Copyright (c) 2022-2024 Core Rule Set project. All rights reserved.
--
-- The OWASP CRS plugins are distributed under
-- Apache Software License (ASL) version 2
-- Please see the enclosed LICENSE file for full details.
-- -----------------------------------------------------------------------

function string_strip(str)
	return string.gsub(str, "^%s*(.-)%s*$", "%1")
end

function main()
	pcall(require, "m")
	local ok, socket = pcall(require, "socket")
	if not ok then
		m.log(2, "False Positive Report Plugin ERROR: LuaSocket library not installed, please install it or disable this plugin.")
		return nil
	end
	local ok, smtp = pcall(require, "socket.smtp")
	if not ok then
		m.log(2, "False Positive Report Plugin ERROR: LuaSocket library not installed, please install it or disable this plugin.")
		return nil
	end
	local filter_rules = {}
	for id in string.gmatch(m.getvar("tx.false-positive-report-plugin_filter_id", "none"), "%d+") do
		filter_rules[id] = true
	end
	local ignore_rules = {}
	for id in string.gmatch(m.getvar("tx.false-positive-report-plugin_filter_ignore_id", "none"), "%d+") do
		ignore_rules[id] = true
	end
	local ignore_messages = {}
	for i = 1, 100 do
		local c = m.getvar(string.format("tx.false-positive-report-plugin_filter_ignore_msg_%s", i), "none")
		if c == nil or c == "" then
			break
		end
		ignore_messages[i] = c
	end
	local ignore_server_names = {}
	for i = 1, 100 do
		local c = m.getvar(string.format("tx.false-positive-report-plugin_filter_ignore_server_name_%s", i), "none")
		if c == nil or c == "" then
			break
		end
		ignore_server_names[i] = c
	end
	local ignore_request_uris = {}
	for i = 1, 100 do
		local c = m.getvar(string.format("tx.false-positive-report-plugin_filter_ignore_request_uri_%s", i), "none")
		if c == nil or c == "" then
			break
		end
		ignore_request_uris[i] = c
	end
	local webserver_error_log = m.getvars("WEBSERVER_ERROR_LOG", "none")
	local ignore_pcre_errors = m.getvar("tx.false-positive-report-plugin_filter_ignore_pcre_limits_error", "none")
	local server_name = m.getvar("SERVER_NAME", "none")
	local request_line = m.getvar("REQUEST_LINE", {"none", "urlDecode"})
	-- As we are running in phase 5, REQUEST_URI could already be rewritten by, for example, mod_rewrite. We need to get it from REQUEST_LINE.
	local request_uri = string.match(request_line, "^[A-Z]+ (.-) HTTP/[0-9\.]+$")
	-- Stripping query string data. 
	if string.find(request_uri, "?") then
		-- Getting first value from iterator.
		request_uri = string.gmatch(request_uri, "(.-)?")()
	end
	local ok = true
	for k2, v2 in pairs(ignore_server_names) do
		--m.log(2, string.format("!!! DEBUG using pattern %s to match server_name %s", v2, server_name))
		if string.match(server_name, v2) then
			--m.log(2, string.format("!!! DEBUG ignoring server_name %s using pattern %s", server_name, v2))
			ok = false
			break
		end
	end
	if ok then
		for k2, v2 in pairs(ignore_request_uris) do
			--m.log(2, string.format("!!! DEBUG using pattern %s to match request_line %s", v2, request_uri))
			if string.match(request_uri, v2) then
				--m.log(2, string.format("!!! DEBUG ignoring request_line %s using pattern %s", request_uri, v2))
				ok = false
				break
			end
		end
		if ok then
			local logs = {}
			local logs_all = {}
			local rules_data = {}
			local send_response_body = false
			for k, v in pairs(webserver_error_log) do
				table.insert(logs_all, v["value"])
				if string.match(v["value"], "ModSecurity") then
					if ignore_pcre_errors == "0" or (ignore_pcre_errors == "1" and string.match(v["value"], "PCRE limits exceeded") == nil) then
						rule_id, rule_msg, rule_data = string.match(v["value"], ' %[id "(%d+)"%] %[msg "(.-)"%] %[data "(.-)"%] %[severity ')
						if rule_id ~= nil and not ignore_rules[rule_id] and (next(filter_rules) == nil or filter_rules[rule_id]) then
							ok = true
							if ok then
								for k2, v2 in pairs(ignore_messages) do
									--m.log(2, string.format("!!! DEBUG using pattern %s to match message %s", v2, rule_msg))
									if string.match(rule_msg, v2) then
										--m.log(2, string.format("!!! DEBUG ignoring message %s using pattern %s", rule_msg, v2))
										ok = false
										break
									end
								end
							end
							if ok then
								table.insert(logs, v["value"])
								variable = string.match(v["value"], 'Pattern match ".-" at (.-)%. ')
								if variable == nil then
									variable = string.match(v["value"], "Matched Data: .- found within (.-): ")
									if variable == nil then
										variable = string.match(v["value"], 'String match within ".-" at (.-)%. ')
										if variable == nil then
											variable = string.match(v["value"], 'String match ".-" at (.-)%. ')
											if variable == nil then
												variable = string.match(v["value"], 'Matched phrase ".-" at (.+)%. %[file')
												if variable == nil then
													variable = string.match(v["value"], 'Match of ".-" against "(.-)" required%. ')
													if variable == nil then
														variable = string.match(v["value"], "Found %d+ byte%(s%) in (.-) outside range:")
														if variable == nil then
															variable = string.match(v["value"], "Operator EQ matched %d+ at (.-)%. ")
															if variable == nil then
																variable = string.match(v["value"], "Invalid URL Encoding: Non%-hexadecimal digits used at (.-)%. ")
																if variable == nil then
																	variable = string.match(v["value"], "Not enough characters at the end of input at (.-)%. ")
																	if variable == nil then
																		m.log(2, string.format("!!! DEBUG: %s !!!", v["value"]))
																		return nil
																	end
																end
															end
														end
													end
												end
											end
										end
									end
								end
								if variable == "RESPONSE_BODY" or variable == "TX:response_body_decompressed" then
									send_response_body = true
								end
								r = {}
								r["id"] = rule_id
								r["variable"] = variable
								r["data"] = rule_data
								table.insert(rules_data, r)
							end
						end
					end
				end
			end
			if next(logs) then
				local smtp_from = m.getvar("tx.false-positive-report-plugin_smtp_from", "none")
				local smtp_to = m.getvar("tx.false-positive-report-plugin_smtp_to", "none")
				local hostname = socket.dns.gethostname()
				local time_day = m.getvar("TIME_DAY", "none")
				local time_mon = m.getvar("TIME_MON", "none")
				local time_year = m.getvar("TIME_YEAR", "none")
				local time_hour = m.getvar("TIME_HOUR", "none")
				local time_min = m.getvar("TIME_MIN", "none")
				local time_sec = m.getvar("TIME_SEC", "none")
				local remote_addr = m.getvar("REMOTE_ADDR", "none")
				local unique_id = m.getvar("UNIQUE_ID", "none")
				local response_status = m.getvar("RESPONSE_STATUS", "none")
				local request_headers = m.getvars("REQUEST_HEADERS", "none")
				local args_post = m.getvars("ARGS_POST", "none")
				local request_body = m.getvar("REQUEST_BODY", "none")
				local full_request = string_strip(m.getvar("FULL_REQUEST", "none"))
				local response_headers_table = { [1] = "Response headers are retrieved only if at least one rule matches response body." }
				local response_body = "Response body is retrieved only if at least one rule matches it."
				if send_response_body then
					response_body = m.getvar("tx.response_body_decompressed", "none")
					if response_body == nil then
						response_body = m.getvar("RESPONSE_BODY", "none")
					end
					response_headers = m.getvars("RESPONSE_HEADERS", "none")
					response_headers_table = {}
					for k, header in pairs(response_headers) do
						table.insert(response_headers_table, string.format("%s: %s", string.sub(header["name"], 18), header["value"]))
					end
				end
				if request_body == nil then
					request_body = ""
				end
				local request_headers_table = {}
				for k, header in pairs(request_headers) do
					table.insert(request_headers_table, string.format("%s: %s", string.sub(header["name"], 17), header["value"]))
				end
				local args = {}
				for k, arg in pairs(args_post) do
					table.insert(args, string.format("%s: %s", string.sub(arg["name"], 11), arg["value"]))
				end
				local whitelist = {}
				local transition_table_variables = {
					["951110"] = "TX:sql_error_match",
					["951120"] = "TX:sql_error_match",
					["951130"] = "TX:sql_error_match",
					["951140"] = "TX:sql_error_match",
					["951150"] = "TX:sql_error_match",
					["951160"] = "TX:sql_error_match",
					["951170"] = "TX:sql_error_match",
					["951180"] = "TX:sql_error_match",
					["951190"] = "TX:sql_error_match",
					["951200"] = "TX:sql_error_match",
					["951210"] = "TX:sql_error_match",
					["951220"] = "TX:sql_error_match",
					["951230"] = "TX:sql_error_match",
					["951240"] = "TX:sql_error_match",
					["951250"] = "TX:sql_error_match",
					["951260"] = "TX:sql_error_match"
				}
				for k, value in pairs(rules_data) do
					if transition_table_variables[value["id"]] ~= nil then
						table.insert(whitelist, string.format("ctl:ruleRemoveTargetById=%s;%s", value["id"], transition_table_variables[value["id"]]))
					elseif value["variable"] == "TX:extension" then
						table.insert(whitelist, string.format("setvar:'tx.restricted_extensions=%%{tx.restricted_extensions} %s/'", value["data"]))
					elseif value["variable"] == "TX:content_type" then
						table.insert(whitelist, string.format("setvar:'tx.allowed_request_content_type=%%{tx.allowed_request_content_type} %s'", value["data"]))
					elseif value["variable"] == "REQUEST_METHOD" then
						table.insert(whitelist, string.format("setvar:'tx.allowed_methods=%%{tx.allowed_methods} %s'", value["data"]))
					else
						table.insert(whitelist, string.format("ctl:ruleRemoveTargetById=%s;%s", value["id"], value["variable"]))
					end
				end
				local content = string.format(
[[Hi, this is OWASP Core Rule Set False Positive Report Plugin!

According to your configuration, blocking of this request may be based on false positive alarms.

=== BASIC DATA ===
DATETIME: %s-%s-%s %s:%s:%s
UNIQUE_ID: %s

REQUEST_LINE: %s
SERVER_NAME: %s
REMOTE_ADDR: %s

RESPONSE_STATUS: %s

=== EXCLUSION RULE SUGGESTION ===
SecRule REQUEST_FILENAME "@endsWith %s" \
    "id:<fix-me>,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    %s"

=== REQUEST HEADERS ===
%s

=== POST ARGUMENTS ===
%s

=== RAW REQUEST BODY ===
%s

=== FILTERED LOGS ===
%s

=== ALL LOGS ===
%s

=== FULL REQUEST ===
%s

=== RESPONSE HEADERS ===
%s

=== RESPONSE BODY ===
%s]], time_year, time_mon, time_day, time_hour, time_min, time_sec, unique_id, request_line, server_name, remote_addr, response_status, request_uri, table.concat(whitelist, ",\\\n    "), table.concat(request_headers_table, "\n"), table.concat(args, "\n"), request_body, table.concat(logs, "\n\n"), table.concat(logs_all, "\n\n"), full_request, table.concat(response_headers_table, "\n"), response_body)
				smtp_headers = {}
				smtp_headers["from"] = smtp_from
				smtp_headers["to"] = smtp_to
				smtp_headers["subject"] = string.gsub(m.getvar("tx.false-positive-report-plugin_smtp_subject", "none"), "<server_hostname>", hostname)
				smtp_headers["subject"] = string.gsub(smtp_headers["subject"], "<host_header>", server_name)
				smtp_headers["message-id"] = string.format("<%s@%s>", unique_id, string.match(smtp_from, "@(.+)$"))
				mesgt = {
					headers = smtp_headers,
					body = content
				}

				smtpparams = {
					from = string.format("<%s>", smtp_from),
					rcpt = string.format("<%s>", smtp_to),
					source = smtp.message(mesgt),
					server = m.getvar("tx.false-positive-report-plugin_smtp_server", "none"),
					port = m.getvar("tx.false-positive-report-plugin_smtp_port", "none")
				}
				smtp_user = m.getvar("tx.false-positive-report-plugin_smtp_user", "none")
				if smtp_user ~= "" then
					smtpparams["user"] = smtp_user
					smtpparams["password"] = m.getvar("tx.false-positive-report-plugin_smtp_password", "none")
				end
				r, e = smtp.send(smtpparams)
				if r == nil then
					m.log(2, string.format("False Positive Report Plugin ERROR: Cannot send e-mail: %s.", e))
				end
			end
		end
	end
	return nil
end
