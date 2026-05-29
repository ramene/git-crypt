/*
 * Copyright 2024 git-crypt-revived contributors
 *
 * This file is part of git-crypt.
 *
 * git-crypt is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * git-crypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with git-crypt.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7:
 *
 * If you modify the Program, or any covered work, by linking or
 * combining it with the OpenSSL project's OpenSSL library (or a
 * modified version of that library), containing parts covered by the
 * terms of the OpenSSL or SSLeay licenses, the licensors of the Program
 * grant you additional permission to convey the resulting work.
 * Corresponding Source for a non-source form of such a combination
 * shall include the source code for the parts of OpenSSL used as well
 * as that of the covered work.
 */

#ifdef _WIN32
#error "License server requires POSIX sockets (Linux/macOS)"
#endif

#include "license_server.hpp"
#include "license.hpp"
#include "license_gate.hpp"
#include "ssh_signing.hpp"
#include "util.hpp"
#include "commands.hpp"

#include <string>
#include <sstream>
#include <iostream>
#include <cstring>
#include <cerrno>
#include <vector>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>

static volatile sig_atomic_t running = 1;

static void signal_handler (int)
{
	running = 0;
}

static std::string json_extract (const std::string& body, const std::string& key)
{
	std::string needle = "\"" + key + "\":\"";
	std::string::size_type pos = body.find(needle);
	if (pos == std::string::npos) {
		needle = "\"" + key + "\": \"";
		pos = body.find(needle);
		if (pos == std::string::npos) {
			return "";
		}
	}
	pos += needle.size();
	std::string::size_type end = body.find('"', pos);
	if (end == std::string::npos) {
		return "";
	}
	return body.substr(pos, end - pos);
}

static std::string json_license (const License& lic)
{
	std::string json;
	json += "{";
	json += "\"id\":\"" + lic.id + "\",";
	json += "\"licensee_fingerprint\":\"" + lic.licensee_fingerprint + "\",";
	json += "\"licensee_wallet\":\"" + lic.licensee_wallet + "\",";
	json += "\"scope\":\"" + lic.scope + "\",";
	json += "\"issued_at\":\"" + lic.issued_at + "\",";
	json += "\"expires_at\":\"" + lic.expires_at + "\",";
	json += "\"status\":\"" + lic.status + "\",";
	json += "\"anchor_tx\":\"" + lic.anchor_tx + "\",";
	json += "\"anchor_rpc\":\"" + lic.anchor_rpc + "\"";
	json += "}";
	return json;
}

static std::string http_response (int status_code, const std::string& status_text,
				  const std::string& body)
{
	std::ostringstream resp;
	resp << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";
	resp << "Content-Type: application/json\r\n";
	resp << "Content-Length: " << body.size() << "\r\n";
	resp << "Connection: close\r\n";
	resp << "\r\n";
	resp << body;
	return resp.str();
}

static std::string handle_verify (int port)
{
	std::string body;
	body += "{";
	body += "\"status\":\"payment_required\",";
	body += "\"message\":\"License requires payment\",";
	body += "\"accepts\":\"EVM\",";
	body += "\"port\":" + std::to_string(port);
	body += "}";
	return http_response(402, "Payment Required", body);
}

static std::string handle_issue (const std::string& request_body, const std::string& rpc_url)
{
	std::string tx_hash = json_extract(request_body, "payment_proof");
	std::string fingerprint = json_extract(request_body, "licensee_fingerprint");
	std::string scope = json_extract(request_body, "scope");
	std::string expires = json_extract(request_body, "expires");

	if (tx_hash.empty() || fingerprint.empty()) {
		return http_response(400, "Bad Request",
			"{\"error\":\"bad_request\",\"message\":\"missing payment_proof or licensee_fingerprint\"}");
	}

	if (scope.empty()) {
		scope = "*";
	}
	if (expires.empty()) {
		expires = "90d";
	}

	try {
		if (!license_verify_onchain(tx_hash, rpc_url)) {
			return http_response(400, "Bad Request",
				"{\"error\":\"payment_invalid\",\"message\":\"on-chain verification failed\"}");
		}

		License lic = license_create(fingerprint, "", scope, expires);
		lic.anchor_tx = tx_hash;
		lic.anchor_rpc = rpc_url;
		license_save(lic);

		std::string key_path = ssh_get_signing_key_path();
		if (!key_path.empty()) {
			license_sign(lic.id, key_path);
		}

		return http_response(200, "OK", json_license(lic));

	} catch (const Error& e) {
		return http_response(500, "Internal Server Error",
			"{\"error\":\"internal_error\",\"message\":\"" + e.message + "\"}");
	} catch (const Ssh_signing_error& e) {
		return http_response(500, "Internal Server Error",
			"{\"error\":\"internal_error\",\"message\":\"" + e.message + "\"}");
	} catch (...) {
		return http_response(500, "Internal Server Error",
			"{\"error\":\"internal_error\",\"message\":\"unexpected error\"}");
	}
}

static std::string handle_licenses ()
{
	try {
		std::vector<std::string> ids = license_list_ids();
		std::string body = "[";
		bool first = true;
		for (size_t i = 0; i < ids.size(); ++i) {
			License lic = license_load(ids[i]);
			if (!license_is_valid(lic)) {
				continue;
			}
			if (!first) {
				body += ",";
			}
			body += json_license(lic);
			first = false;
		}
		body += "]";
		return http_response(200, "OK", body);

	} catch (const Error& e) {
		return http_response(500, "Internal Server Error",
			"{\"error\":\"internal_error\",\"message\":\"" + e.message + "\"}");
	} catch (...) {
		return http_response(500, "Internal Server Error",
			"{\"error\":\"internal_error\",\"message\":\"unexpected error\"}");
	}
}

static std::string handle_health ()
{
	return http_response(200, "OK", "{\"status\":\"ok\"}");
}

static std::string handle_not_found ()
{
	return http_response(404, "Not Found", "{\"error\":\"not_found\"}");
}

static std::string handle_method_not_allowed ()
{
	return http_response(405, "Method Not Allowed", "{\"error\":\"method_not_allowed\"}");
}

static void parse_request (const std::string& raw, std::string& method,
			   std::string& path, std::string& body)
{
	// Parse first line: METHOD /path HTTP/1.x
	std::string::size_type first_space = raw.find(' ');
	if (first_space == std::string::npos) {
		method = "";
		path = "";
		body = "";
		return;
	}
	method = raw.substr(0, first_space);

	std::string::size_type second_space = raw.find(' ', first_space + 1);
	if (second_space == std::string::npos) {
		path = raw.substr(first_space + 1);
	} else {
		path = raw.substr(first_space + 1, second_space - first_space - 1);
	}

	// Body is after \r\n\r\n
	std::string::size_type body_start = raw.find("\r\n\r\n");
	if (body_start != std::string::npos) {
		body = raw.substr(body_start + 4);
	} else {
		body = "";
	}
}

static std::string route_request (const std::string& method, const std::string& path,
				  const std::string& body, int port,
				  const std::string& rpc_url)
{
	if (path == "/health") {
		if (method == "GET") {
			return handle_health();
		}
		return handle_method_not_allowed();
	}

	if (path == "/verify") {
		if (method == "GET") {
			return handle_verify(port);
		}
		return handle_method_not_allowed();
	}

	if (path == "/issue") {
		if (method == "POST") {
			return handle_issue(body, rpc_url);
		}
		return handle_method_not_allowed();
	}

	if (path == "/licenses") {
		if (method == "GET") {
			return handle_licenses();
		}
		return handle_method_not_allowed();
	}

	return handle_not_found();
}

int license_server_run (int port, const std::string& rpc_url)
{
	struct sigaction sa;
	std::memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		std::cerr << "license-server: socket(): " << std::strerror(errno) << std::endl;
		return 1;
	}

	int opt = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr;
	std::memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(static_cast<uint16_t>(port));

	if (bind(server_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
		std::cerr << "license-server: bind(): " << std::strerror(errno) << std::endl;
		close(server_fd);
		return 1;
	}

	if (listen(server_fd, 5) < 0) {
		std::cerr << "license-server: listen(): " << std::strerror(errno) << std::endl;
		close(server_fd);
		return 1;
	}

	std::cerr << "license-server: listening on port " << port << std::endl;

	while (running) {
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		int client_fd = accept(server_fd,
				       reinterpret_cast<struct sockaddr*>(&client_addr),
				       &client_len);
		if (client_fd < 0) {
			if (errno == EINTR) {
				continue;
			}
			std::cerr << "license-server: accept(): " << std::strerror(errno) << std::endl;
			continue;
		}

		char buf[4096];
		ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
		if (n <= 0) {
			close(client_fd);
			continue;
		}
		buf[n] = '\0';

		std::string raw(buf, static_cast<size_t>(n));
		std::string method;
		std::string path;
		std::string body;
		parse_request(raw, method, path, body);

		std::string response = route_request(method, path, body, port, rpc_url);

		const char* resp_data = response.c_str();
		size_t resp_len = response.size();
		size_t written = 0;
		while (written < resp_len) {
			ssize_t w = write(client_fd, resp_data + written, resp_len - written);
			if (w <= 0) {
				break;
			}
			written += static_cast<size_t>(w);
		}

		close(client_fd);
	}

	close(server_fd);
	std::cerr << "license-server: shut down" << std::endl;
	return 0;
}
