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

#include "license.hpp"
#include "ssh_signing.hpp"
#include "util.hpp"
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cstdio>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

static std::vector<std::string> split_tabs (const std::string& line)
{
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
	return fields;
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

static std::string get_repo_root ()
{
	std::vector<std::string>	cmd;
	cmd.push_back("git");
	cmd.push_back("rev-parse");
	cmd.push_back("--show-toplevel");
	std::stringstream	output;
	if (successful_exit(exec_command(cmd, output))) {
		std::string	root = output.str();
		while (!root.empty() && (root.back() == '\n' || root.back() == '\r')) {
			root.pop_back();
		}
		return root;
	}
	return ".";
}

std::string license_generate_id ()
{
	unsigned char	bytes[8];
	if (RAND_bytes(bytes, sizeof(bytes)) != 1) {
		throw std::runtime_error("RAND_bytes failed");
	}
	char	hex[17];
	for (int i = 0; i < 8; ++i) {
		std::snprintf(hex + i * 2, 3, "%02x", bytes[i]);
	}
	return std::string(hex, 16);
}

std::string license_dir (const std::string& id)
{
	return get_repo_root() + "/.git-crypt/licenses/" + id;
}

std::string license_path (const std::string& id)
{
	return license_dir(id) + "/license.txt";
}

std::string license_sig_dir (const std::string& id)
{
	return license_dir(id) + "/signatures";
}

std::string license_sig_path (const std::string& id, const std::string& fingerprint)
{
	return license_sig_dir(id) + "/" + fingerprint + ".sig";
}

License license_create (const std::string& licensee_fingerprint,
			const std::string& licensee_wallet,
			const std::string& scope,
			const std::string& expires_at)
{
	License	lic;
	lic.id = license_generate_id();
	lic.licensee_fingerprint = licensee_fingerprint;
	lic.licensee_wallet = licensee_wallet;
	lic.scope = scope;
	lic.issued_at = iso8601_now();
	lic.expires_at = expires_at;
	lic.status = "active";

	license_save(lic);
	return lic;
}

License license_load (const std::string& id)
{
	License		lic;
	lic.id = id;
	std::string	path = license_path(id);
	std::ifstream	in(path);
	if (!in) {
		throw std::runtime_error("Cannot open license file: " + path);
	}

	std::string	line;
	while (std::getline(in, line)) {
		if (line.empty() || line[0] == '#') {
			continue;
		}
		std::vector<std::string>	fields = split_tabs(line);
		if (fields.size() < 2) {
			continue;
		}
		const std::string&	key = fields[0];
		const std::string&	val = fields[1];

		if (key == "id")			lic.id = val;
		else if (key == "licensee_fingerprint")	lic.licensee_fingerprint = val;
		else if (key == "licensee_wallet")	lic.licensee_wallet = val;
		else if (key == "scope")		lic.scope = val;
		else if (key == "issued_at")		lic.issued_at = val;
		else if (key == "expires_at")		lic.expires_at = val;
		else if (key == "status")		lic.status = val;
		else if (key == "anchor_tx")		lic.anchor_tx = val;
		else if (key == "anchor_rpc")		lic.anchor_rpc = val;
	}
	return lic;
}

void license_save (const License& license)
{
	std::string	path = license_path(license.id);
	mkdir_parent(path);
	std::ofstream	out(path);
	if (!out) {
		throw std::runtime_error("Cannot write license file: " + path);
	}
	out << "# git-crypt license file\n";
	out << "id\t" << license.id << "\n";
	out << "licensee_fingerprint\t" << license.licensee_fingerprint << "\n";
	out << "licensee_wallet\t" << license.licensee_wallet << "\n";
	out << "scope\t" << license.scope << "\n";
	out << "issued_at\t" << license.issued_at << "\n";
	out << "expires_at\t" << license.expires_at << "\n";
	out << "status\t" << license.status << "\n";
	if (!license.anchor_tx.empty()) {
		out << "anchor_tx\t" << license.anchor_tx << "\n";
	}
	if (!license.anchor_rpc.empty()) {
		out << "anchor_rpc\t" << license.anchor_rpc << "\n";
	}
}

void license_sign (const std::string& id, const std::string& key_path)
{
	std::string	path = license_path(id);
	std::ifstream	in(path);
	if (!in) {
		throw std::runtime_error("Cannot read license for signing: " + path);
	}
	std::string	content((std::istreambuf_iterator<char>(in)),
				 std::istreambuf_iterator<char>());
	in.close();

	std::string	signature = ssh_sign(content, key_path);
	std::string	fp = ssh_key_fingerprint(key_path);
	std::string	sig_path = license_sig_path(id, fp);
	mkdir_parent(sig_path);

	std::ofstream	sig_out(sig_path);
	if (!sig_out) {
		throw std::runtime_error("Cannot write signature file: " + sig_path);
	}
	sig_out << signature;
}

bool license_verify_signatures (const std::string& id)
{
	std::string	sig_dir = license_sig_dir(id);
	std::vector<std::string>	entries;
	try {
		entries = get_directory_contents(sig_dir.c_str());
	} catch (...) {
		return false;
	}

	if (entries.empty()) {
		return false;
	}

	std::string	path = license_path(id);
	std::ifstream	in(path);
	if (!in) {
		return false;
	}
	std::string	content((std::istreambuf_iterator<char>(in)),
				 std::istreambuf_iterator<char>());
	in.close();

	for (size_t i = 0; i < entries.size(); ++i) {
		const std::string&	entry = entries[i];
		if (entry.size() < 5 || entry.substr(entry.size() - 4) != ".sig") {
			continue;
		}

		std::string	sig_file = sig_dir + "/" + entry;
		std::ifstream	sig_in(sig_file);
		if (!sig_in) {
			continue;
		}
		std::string	signature((std::istreambuf_iterator<char>(sig_in)),
					   std::istreambuf_iterator<char>());
		sig_in.close();

		// Build a temporary allowed_signers file with the fingerprint from the sig filename
		std::string	fp = entry.substr(0, entry.size() - 4);
		char		tmp_allowed[] = "/tmp/git-crypt-allowed-XXXXXX";
		int		fd = mkstemp(tmp_allowed);
		if (fd < 0) {
			continue;
		}
		std::string	allowed_line = "git-crypt-license " + fp + "\n";
		ssize_t		written = write(fd, allowed_line.data(), allowed_line.size());
		close(fd);
		if (written < 0 || static_cast<size_t>(written) != allowed_line.size()) {
			unlink(tmp_allowed);
			continue;
		}

		bool	valid = ssh_verify(content, signature, tmp_allowed, "git-crypt-license");
		unlink(tmp_allowed);

		if (valid) {
			return true;
		}
	}
	return false;
}

std::vector<std::string> license_list_ids ()
{
	std::vector<std::string>	ids;
	std::string	dir = get_repo_root() + "/.git-crypt/licenses";
	std::vector<std::string>	entries;
	try {
		entries = get_directory_contents(dir.c_str());
	} catch (...) {
		return ids;
	}

	for (size_t i = 0; i < entries.size(); ++i) {
		const std::string&	entry = entries[i];
		if (entry == "." || entry == ".." || entry == "issuer.txt") {
			continue;
		}
		// Check if it's a directory
		struct stat	st;
		std::string	full = dir + "/" + entry;
		if (stat(full.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
			ids.push_back(entry);
		}
	}
	return ids;
}

bool license_scope_contains (const License& license, const std::string& operation)
{
	if (license.scope == "*") {
		return true;
	}
	// Parse comma-separated scope
	size_t	pos = 0;
	while (pos <= license.scope.size()) {
		size_t	next = license.scope.find(',', pos);
		std::string	item;
		if (next == std::string::npos) {
			item = license.scope.substr(pos);
			pos = license.scope.size() + 1;
		} else {
			item = license.scope.substr(pos, next - pos);
			pos = next + 1;
		}
		if (item == operation) {
			return true;
		}
	}
	return false;
}

bool license_is_valid (const License& license)
{
	if (license.status != "active") {
		return false;
	}
	if (license.expires_at.empty()) {
		return true;
	}
	std::string	now = iso8601_now();
	return now < license.expires_at;
}

std::string license_hash (const License& license)
{
	std::string		data = license_serialize(license);
	unsigned char		hash[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);

	char	hex[SHA256_DIGEST_LENGTH * 2 + 1];
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		std::snprintf(hex + i * 2, 3, "%02x", hash[i]);
	}
	return std::string(hex, SHA256_DIGEST_LENGTH * 2);
}

std::string license_serialize (const License& license)
{
	std::ostringstream	out;
	out << "id\t" << license.id << "\n";
	out << "licensee_fingerprint\t" << license.licensee_fingerprint << "\n";
	out << "licensee_wallet\t" << license.licensee_wallet << "\n";
	out << "scope\t" << license.scope << "\n";
	out << "issued_at\t" << license.issued_at << "\n";
	out << "expires_at\t" << license.expires_at << "\n";
	out << "status\t" << license.status << "\n";
	out << "anchor_tx\t" << license.anchor_tx << "\n";
	out << "anchor_rpc\t" << license.anchor_rpc << "\n";
	return out.str();
}

License license_deserialize (const std::string& data)
{
	License		lic;
	std::istringstream	in(data);
	std::string	line;
	while (std::getline(in, line)) {
		if (line.empty() || line[0] == '#') {
			continue;
		}
		std::vector<std::string>	fields = split_tabs(line);
		if (fields.size() < 2) {
			continue;
		}
		const std::string&	key = fields[0];
		const std::string&	val = fields[1];

		if (key == "id")			lic.id = val;
		else if (key == "licensee_fingerprint")	lic.licensee_fingerprint = val;
		else if (key == "licensee_wallet")	lic.licensee_wallet = val;
		else if (key == "scope")		lic.scope = val;
		else if (key == "issued_at")		lic.issued_at = val;
		else if (key == "expires_at")		lic.expires_at = val;
		else if (key == "status")		lic.status = val;
		else if (key == "anchor_tx")		lic.anchor_tx = val;
		else if (key == "anchor_rpc")		lic.anchor_rpc = val;
	}
	return lic;
}

bool license_initialized ()
{
	std::string	path = get_repo_root() + "/.git-crypt/licenses/issuer.txt";
	std::ifstream	in(path);
	return in.good();
}

std::string license_issuer_fingerprint ()
{
	std::string	path = get_repo_root() + "/.git-crypt/licenses/issuer.txt";
	std::ifstream	in(path);
	if (!in) {
		throw std::runtime_error("Cannot read issuer file: " + path);
	}
	std::string	line;
	std::getline(in, line);
	return line;
}
