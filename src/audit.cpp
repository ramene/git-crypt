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

#include "audit.hpp"
#include "util.hpp"
#include "commands.hpp"
#include <openssl/sha.h>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cstdlib>
#include <cstring>

// Audit log format (one entry per line, tab-separated):
// TIMESTAMP\tIDENTITY\tIDENTITY_TYPE\tOPERATION\tKEY_NAME\tFILES\tPREV_HASH\tENTRY_HASH
//
// FILES is comma-separated (empty string if none)
// PREV_HASH is "0" for the first entry

static std::string sha256_hex (const std::string& data)
{
	unsigned char	hash[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);

	static const char	hex_chars[] = "0123456789abcdef";
	std::string		result;
	result.reserve(SHA256_DIGEST_LENGTH * 2);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		result += hex_chars[(hash[i] >> 4) & 0x0f];
		result += hex_chars[hash[i] & 0x0f];
	}
	return result;
}

static std::string iso8601_now ()
{
	std::time_t	now = std::time(0);
	struct tm	tm_buf;
	gmtime_r(&now, &tm_buf);
	char		buf[32];
	std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
	return std::string(buf);
}

std::string audit_log_path ()
{
	// Store in .git-crypt/audit.log
	std::string	git_dir;
	try {
		std::vector<std::string>	cmd;
		cmd.push_back("git");
		cmd.push_back("rev-parse");
		cmd.push_back("--git-dir");
		std::stringstream		output;
		if (successful_exit(exec_command(cmd, output))) {
			git_dir = output.str();
			while (!git_dir.empty() && (git_dir.back() == '\n' || git_dir.back() == '\r')) {
				git_dir.pop_back();
			}
		}
	} catch (...) {
	}
	if (git_dir.empty()) {
		git_dir = ".git";
	}
	return git_dir + "/git-crypt/audit.log";
}

std::string audit_entry_hash (const std::string& timestamp,
			      const std::string& identity,
			      const std::string& identity_type,
			      const std::string& operation,
			      const std::string& key_name,
			      const std::string& prev_hash)
{
	std::string	data;
	data += timestamp;
	data += '\t';
	data += identity;
	data += '\t';
	data += identity_type;
	data += '\t';
	data += operation;
	data += '\t';
	data += key_name;
	data += '\t';
	data += prev_hash;
	return sha256_hex(data);
}

static std::string get_last_hash ()
{
	std::string	path = audit_log_path();
	std::ifstream	in(path);
	if (!in) {
		return "0";
	}

	std::string	last_line;
	std::string	line;
	while (std::getline(in, line)) {
		if (!line.empty()) {
			last_line = line;
		}
	}

	if (last_line.empty()) {
		return "0";
	}

	// Parse entry_hash (last tab-separated field)
	size_t	pos = last_line.rfind('\t');
	if (pos == std::string::npos) {
		return "0";
	}
	return last_line.substr(pos + 1);
}

std::string audit_get_identity (std::string& identity_type)
{
	// Try git config user info first
	std::string	identity;
	try {
		identity = get_git_config("user.email");
		identity_type = "git";
		return identity;
	} catch (...) {
	}
	try {
		identity = get_git_config("user.name");
		identity_type = "git";
		return identity;
	} catch (...) {
	}

	// Fall back to system username
	const char*	user = std::getenv("USER");
	if (!user) user = std::getenv("USERNAME");
	if (user) {
		identity_type = "local";
		return std::string(user);
	}

	identity_type = "unknown";
	return "unknown";
}

void audit_log_operation (const std::string& operation,
			  const std::string& identity,
			  const std::string& identity_type,
			  const char* key_name,
			  const std::vector<std::string>& files)
{
	std::string	path = audit_log_path();
	mkdir_parent(path);

	std::string	timestamp = iso8601_now();
	std::string	kn = key_name ? key_name : "default";
	std::string	prev_hash = get_last_hash();

	// Build files string (comma-separated)
	std::string	files_str;
	for (size_t i = 0; i < files.size(); ++i) {
		if (i > 0) files_str += ',';
		files_str += files[i];
	}

	std::string	entry_hash = audit_entry_hash(timestamp, identity, identity_type,
						      operation, kn, prev_hash);

	// Append to log
	std::ofstream	out(path, std::ios::app);
	if (!out) {
		return;	// Silently fail — audit is best-effort
	}

	out << timestamp << '\t'
	    << identity << '\t'
	    << identity_type << '\t'
	    << operation << '\t'
	    << kn << '\t'
	    << files_str << '\t'
	    << prev_hash << '\t'
	    << entry_hash << std::endl;
}

static Audit_entry parse_audit_line (const std::string& line)
{
	Audit_entry	entry;
	std::vector<std::string>	fields;
	size_t		pos = 0;

	while (pos <= line.size()) {
		size_t	next = line.find('\t', pos);
		if (next == std::string::npos) {
			fields.push_back(line.substr(pos));
			break;
		}
		fields.push_back(line.substr(pos, next - pos));
		pos = next + 1;
	}

	if (fields.size() >= 8) {
		entry.timestamp = fields[0];
		entry.identity = fields[1];
		entry.identity_type = fields[2];
		entry.operation = fields[3];
		entry.key_name = fields[4];

		// Parse files (comma-separated)
		if (!fields[5].empty()) {
			size_t	fpos = 0;
			while (fpos <= fields[5].size()) {
				size_t	fnext = fields[5].find(',', fpos);
				if (fnext == std::string::npos) {
					entry.files.push_back(fields[5].substr(fpos));
					break;
				}
				entry.files.push_back(fields[5].substr(fpos, fnext - fpos));
				fpos = fnext + 1;
			}
		}

		entry.prev_hash = fields[6];
		entry.entry_hash = fields[7];
	}

	return entry;
}

std::vector<Audit_entry> audit_read_log ()
{
	std::vector<Audit_entry>	entries;
	std::string	path = audit_log_path();
	std::ifstream	in(path);
	if (!in) {
		return entries;
	}

	std::string	line;
	while (std::getline(in, line)) {
		if (!line.empty()) {
			entries.push_back(parse_audit_line(line));
		}
	}
	return entries;
}

size_t audit_verify_chain (const std::vector<Audit_entry>& entries)
{
	if (entries.empty()) {
		return 0;
	}

	size_t	valid = 0;
	for (size_t i = 0; i < entries.size(); ++i) {
		const Audit_entry&	e = entries[i];

		// Check prev_hash
		if (i == 0) {
			if (e.prev_hash != "0") {
				break;
			}
		} else {
			if (e.prev_hash != entries[i - 1].entry_hash) {
				break;
			}
		}

		// Verify entry_hash
		std::string	expected = audit_entry_hash(e.timestamp, e.identity, e.identity_type,
							   e.operation, e.key_name, e.prev_hash);
		if (e.entry_hash != expected) {
			break;
		}

		++valid;
	}

	return valid;
}
