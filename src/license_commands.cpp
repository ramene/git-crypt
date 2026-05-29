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

#include "license_commands.hpp"
#include "license.hpp"
#include "license_gate.hpp"
#include "license_server.hpp"
#include "ssh_signing.hpp"
#include "util.hpp"
#include "parse_options.hpp"
#include "commands.hpp"
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cstdlib>
#include <sys/stat.h>

static std::string get_repo_root ()
{
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("rev-parse");
	command.push_back("--show-toplevel");

	std::stringstream		output;
	if (!successful_exit(exec_command(command, output))) {
		throw Error("Failed to get repository root - is this a git repository?");
	}
	std::string	root;
	std::getline(output, root);
	while (!root.empty() && (root.back() == '\n' || root.back() == '\r')) {
		root.pop_back();
	}
	return root;
}

static std::string iso8601_add_days (int days)
{
	time_t		now = time(0);
	now += static_cast<time_t>(days) * 86400;
	struct tm	utc;
	gmtime_r(&now, &utc);
	char		buf[64];
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
	return std::string(buf);
}

// Parse a duration spec like "90d", "1y", or an ISO 8601 timestamp.
// Returns an ISO 8601 timestamp string.
static std::string parse_duration (const std::string& spec)
{
	if (spec.empty()) {
		throw Error("Empty duration specification");
	}

	// Check if it looks like an ISO 8601 date (starts with digit and contains '-')
	if (spec.size() >= 10 && spec[4] == '-') {
		return spec;
	}

	char		suffix = spec[spec.size() - 1];
	std::string	num_str = spec.substr(0, spec.size() - 1);
	int		num = std::atoi(num_str.c_str());

	if (num <= 0) {
		throw Error("Invalid duration: " + spec);
	}

	int	days = 0;
	switch (suffix) {
	case 'd':
		days = num;
		break;
	case 'w':
		days = num * 7;
		break;
	case 'm':
		days = num * 30;
		break;
	case 'y':
		days = num * 365;
		break;
	default:
		throw Error("Unknown duration suffix '" + std::string(1, suffix) + "' in: " + spec);
	}

	return iso8601_add_days(days);
}

// ---------------------------------------------------------------------------
// Help functions
// ---------------------------------------------------------------------------

void help_license_init (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt license init [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --force                     Reinitialize even if already set up" << std::endl;
	out << std::endl;
	out << "Initialize the licensing system for this repository." << std::endl;
	out << "Creates .git-crypt/licenses/ and records the issuer fingerprint." << std::endl;
	out << std::endl;
}

void help_license_issue (std::ostream& out)
{
	out << "Usage: git-crypt license issue [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --to FINGERPRINT            Licensee SSH key fingerprint (required)" << std::endl;
	out << "    --wallet ADDRESS            Licensee Ethereum wallet address" << std::endl;
	out << "    --scope OPS                 Comma-separated operations (default: *)" << std::endl;
	out << "    --expires DURATION          Duration (90d, 1y) or ISO date (required)" << std::endl;
	out << std::endl;
	out << "Issue a new license to a recipient." << std::endl;
	out << std::endl;
}

void help_license_verify (std::ostream& out)
{
	out << "Usage: git-crypt license verify <LICENSE-ID> [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --onchain                   Also verify on-chain anchor" << std::endl;
	out << std::endl;
	out << "Verify a license's signatures and validity." << std::endl;
	out << std::endl;
}

void help_license_revoke (std::ostream& out)
{
	out << "Usage: git-crypt license revoke <LICENSE-ID> [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --anchor                    Anchor revocation on-chain" << std::endl;
	out << "    --rpc-url URL               Ethereum JSON-RPC endpoint" << std::endl;
	out << "    --from ADDRESS              Ethereum address to send from" << std::endl;
	out << std::endl;
	out << "Revoke a license." << std::endl;
	out << std::endl;
}

void help_license_list (std::ostream& out)
{
	out << "Usage: git-crypt license list [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --all                       Include revoked and expired licenses" << std::endl;
	out << "    --json                      Output in JSON format (for x402)" << std::endl;
	out << std::endl;
	out << "List licenses in this repository." << std::endl;
	out << std::endl;
}

void help_license_show (std::ostream& out)
{
	out << "Usage: git-crypt license show <LICENSE-ID>" << std::endl;
	out << std::endl;
	out << "Show detailed information about a license." << std::endl;
	out << std::endl;
}

void help_license_anchor (std::ostream& out)
{
	out << "Usage: git-crypt license anchor <LICENSE-ID> [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --rpc-url URL               Ethereum JSON-RPC endpoint (required)" << std::endl;
	out << "    --from ADDRESS              Ethereum address to send from (required)" << std::endl;
	out << std::endl;
	out << "Anchor a license hash on an Ethereum-compatible blockchain." << std::endl;
	out << std::endl;
}

void help_license_import (std::ostream& out)
{
	out << "Usage: git-crypt license import <FILE>" << std::endl;
	out << std::endl;
	out << "Import a license from a file." << std::endl;
	out << std::endl;
}

void help_license_export (std::ostream& out)
{
	out << "Usage: git-crypt license export <LICENSE-ID> [FILE]" << std::endl;
	out << std::endl;
	out << "Export a license to a file. Default filename: <id>.license" << std::endl;
	out << std::endl;
}

void help_license_check (std::ostream& out)
{
	out << "Usage: git-crypt license check [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --operation OP              Operation to check (default: *)" << std::endl;
	out << std::endl;
	out << "Check if the current user has a valid license for the given operation." << std::endl;
	out << std::endl;
}

void help_license_serve (std::ostream& out)
{
	out << "Usage: git-crypt license serve [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --port PORT                 Listen port (default: 8402)" << std::endl;
	out << "    --rpc-url URL               Ethereum JSON-RPC endpoint (required)" << std::endl;
	out << std::endl;
	out << "Start an x402 HTTP license payment server." << std::endl;
	out << std::endl;
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

int license_cmd_init (int argc, const char** argv)
{
	bool		force = false;
	Options_list	options;
	options.push_back(Option_def("--force", &force));

	int	argi = parse_options(options, argc, argv);
	if (argc - argi != 0) {
		help_license_init(std::clog);
		return 2;
	}

	if (license_initialized() && !force) {
		std::clog << "Licensing already initialized. Use --force to reinitialize." << std::endl;
		return 1;
	}

	std::string	repo_root = get_repo_root();
	std::string	licenses_dir = repo_root + "/.git-crypt/licenses";

	// Create licenses directory
	mkdir_parent(licenses_dir + "/dummy");
	mkdir(licenses_dir.c_str(), 0777);

	// Get signing key and compute fingerprint
	std::string	key_path = ssh_get_signing_key_path();
	if (key_path.empty()) {
		std::clog << "Error: no SSH signing key configured." << std::endl;
		std::clog << "Set one with: git config user.signingkey PATH" << std::endl;
		return 1;
	}

	std::string	fingerprint = ssh_key_fingerprint(key_path);
	if (fingerprint.empty()) {
		std::clog << "Error: could not compute fingerprint for key: " << key_path << std::endl;
		return 1;
	}

	// Write issuer.txt
	std::string	issuer_path = licenses_dir + "/issuer.txt";
	std::ofstream	out(issuer_path.c_str());
	if (!out) {
		std::clog << "Error: could not write " << issuer_path << std::endl;
		return 1;
	}
	out << fingerprint << std::endl;
	out.close();

	std::cout << "Licensing initialized." << std::endl;
	std::cout << "Issuer fingerprint: " << fingerprint << std::endl;
	return 0;
}

int license_cmd_issue (int argc, const char** argv)
{
	const char*	to_fingerprint = 0;
	const char*	wallet = 0;
	const char*	scope = 0;
	const char*	expires = 0;
	Options_list	options;
	options.push_back(Option_def("--to", &to_fingerprint));
	options.push_back(Option_def("--wallet", &wallet));
	options.push_back(Option_def("--scope", &scope));
	options.push_back(Option_def("--expires", &expires));

	int	argi = parse_options(options, argc, argv);
	if (argc - argi != 0) {
		help_license_issue(std::clog);
		return 2;
	}

	if (!license_initialized()) {
		std::clog << "Error: licensing not initialized. Run 'git-crypt license init' first." << std::endl;
		return 1;
	}

	if (!to_fingerprint) {
		std::clog << "Error: --to FINGERPRINT is required." << std::endl;
		return 2;
	}

	if (!expires) {
		std::clog << "Error: --expires DURATION is required." << std::endl;
		return 2;
	}

	std::string	scope_str = scope ? scope : "*";
	std::string	wallet_str = wallet ? wallet : "";
	std::string	expires_at;

	try {
		expires_at = parse_duration(expires);
	} catch (const Error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	// Create the license
	License	lic;
	try {
		lic = license_create(to_fingerprint, wallet_str, scope_str, expires_at);
	} catch (const Error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	// Sign with issuer key
	std::string	key_path = ssh_get_signing_key_path();
	if (key_path.empty()) {
		std::clog << "Error: no SSH signing key configured." << std::endl;
		return 1;
	}

	try {
		license_sign(lic.id, key_path);
	} catch (const Error& e) {
		std::clog << "Error signing license: " << e.message << std::endl;
		return 1;
	}

	std::cout << "License issued: " << lic.id << std::endl;
	std::cout << "  To:       " << lic.licensee_fingerprint << std::endl;
	if (!lic.licensee_wallet.empty()) {
		std::cout << "  Wallet:   " << lic.licensee_wallet << std::endl;
	}
	std::cout << "  Scope:    " << lic.scope << std::endl;
	std::cout << "  Expires:  " << lic.expires_at << std::endl;
	return 0;
}

int license_cmd_verify (int argc, const char** argv)
{
	bool		onchain = false;
	Options_list	options;
	options.push_back(Option_def("--onchain", &onchain));

	int	argi = parse_options(options, argc, argv);
	if (argc - argi != 1) {
		help_license_verify(std::clog);
		return 2;
	}

	std::string	id = argv[argi];

	License	lic;
	try {
		lic = license_load(id);
	} catch (const Error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	bool	valid = license_is_valid(lic);
	bool	sigs_ok = license_verify_signatures(id);

	std::cout << "License:     " << id << std::endl;
	std::cout << "Status:      " << lic.status << std::endl;
	std::cout << "Valid:       " << (valid ? "yes" : "no") << std::endl;
	std::cout << "Signatures:  " << (sigs_ok ? "verified" : "INVALID") << std::endl;

	if (onchain) {
		if (lic.anchor_tx.empty()) {
			std::cout << "On-chain:    not anchored" << std::endl;
		} else {
			bool	chain_ok = license_verify_onchain(lic.anchor_tx, lic.anchor_rpc);
			std::cout << "On-chain:    " << (chain_ok ? "confirmed" : "UNCONFIRMED") << std::endl;
			std::cout << "Tx hash:     " << lic.anchor_tx << std::endl;
		}
	}

	return (valid && sigs_ok) ? 0 : 1;
}

int license_cmd_revoke (int argc, const char** argv)
{
	bool		anchor = false;
	const char*	rpc_url = 0;
	const char*	from_address = 0;
	Options_list	options;
	options.push_back(Option_def("--anchor", &anchor));
	options.push_back(Option_def("--rpc-url", &rpc_url));
	options.push_back(Option_def("--from", &from_address));

	int	argi = parse_options(options, argc, argv);
	if (argc - argi != 1) {
		help_license_revoke(std::clog);
		return 2;
	}

	std::string	id = argv[argi];

	License	lic;
	try {
		lic = license_load(id);
	} catch (const Error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	if (lic.status == "revoked") {
		std::clog << "License " << id << " is already revoked." << std::endl;
		return 1;
	}

	lic.status = "revoked";

	try {
		license_save(lic);
	} catch (const Error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	std::cout << "License " << id << " revoked." << std::endl;

	if (anchor) {
		if (!rpc_url) {
			std::clog << "Error: --rpc-url is required with --anchor." << std::endl;
			return 2;
		}
		if (!from_address) {
			std::clog << "Error: --from is required with --anchor." << std::endl;
			return 2;
		}

		std::string	hash = license_hash(lic);

		std::vector<std::string>	cmd;
		cmd.push_back("cast");
		cmd.push_back("send");
		cmd.push_back("--rpc-url");
		cmd.push_back(rpc_url);
		cmd.push_back("--account");
		cmd.push_back(from_address);
		cmd.push_back(from_address);
		cmd.push_back("0x" + hash);

		std::stringstream	output;
		if (!successful_exit(exec_command(cmd, output))) {
			std::clog << "Error: failed to anchor revocation on-chain." << std::endl;
			return 1;
		}

		// Parse tx hash
		std::string	tx_hash;
		std::string	line;
		while (std::getline(output, line)) {
			if (line.find("transactionHash") != std::string::npos) {
				size_t	pos = line.find("0x");
				if (pos != std::string::npos) {
					tx_hash = line.substr(pos);
					while (!tx_hash.empty() && (tx_hash.back() == '\n' || tx_hash.back() == '\r' || tx_hash.back() == ' ')) {
						tx_hash.pop_back();
					}
				}
			}
		}

		if (!tx_hash.empty()) {
			lic.anchor_tx = tx_hash;
			lic.anchor_rpc = rpc_url;
			license_save(lic);
			std::cout << "Revocation anchored: " << tx_hash << std::endl;
		} else {
			std::clog << "Warning: transaction sent but hash could not be parsed." << std::endl;
		}
	}

	return 0;
}

int license_cmd_list (int argc, const char** argv)
{
	bool		all = false;
	bool		json = false;
	Options_list	options;
	options.push_back(Option_def("--all", &all));
	options.push_back(Option_def("--json", &json));

	int	argi = parse_options(options, argc, argv);
	if (argc - argi != 0) {
		help_license_list(std::clog);
		return 2;
	}

	if (!license_initialized()) {
		std::clog << "Licensing not initialized." << std::endl;
		return 1;
	}

	std::vector<std::string>	ids = license_list_ids();

	if (json) {
		std::cout << "[" << std::endl;
	}

	int	count = 0;
	for (size_t i = 0; i < ids.size(); ++i) {
		License	lic;
		try {
			lic = license_load(ids[i]);
		} catch (...) {
			continue;
		}

		if (!all && !license_is_valid(lic)) {
			continue;
		}

		if (json) {
			if (count > 0) {
				std::cout << "," << std::endl;
			}
			std::cout << "  {";
			std::cout << "\"id\":\"" << lic.id << "\",";
			std::cout << "\"fingerprint\":\"" << lic.licensee_fingerprint << "\",";
			std::cout << "\"scope\":\"" << lic.scope << "\",";
			std::cout << "\"expires\":\"" << lic.expires_at << "\",";
			std::cout << "\"status\":\"" << lic.status << "\"";
			std::cout << "}";
		} else {
			std::cout << lic.id << "  "
				  << lic.licensee_fingerprint.substr(0, 24) << "  "
				  << lic.scope << "  "
				  << lic.expires_at << "  "
				  << lic.status << std::endl;
		}

		++count;
	}

	if (json) {
		std::cout << std::endl << "]" << std::endl;
	} else if (count == 0) {
		std::cout << "No licenses found." << std::endl;
	} else {
		std::cout << std::endl << "Total: " << count << " license(s)" << std::endl;
	}

	return 0;
}

int license_cmd_show (int argc, const char** argv)
{
	Options_list	options;

	int	argi = parse_options(options, argc, argv);
	if (argc - argi != 1) {
		help_license_show(std::clog);
		return 2;
	}

	std::string	id = argv[argi];

	License	lic;
	try {
		lic = license_load(id);
	} catch (const Error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	std::cout << "License ID:    " << lic.id << std::endl;
	std::cout << "Fingerprint:   " << lic.licensee_fingerprint << std::endl;
	if (!lic.licensee_wallet.empty()) {
		std::cout << "Wallet:        " << lic.licensee_wallet << std::endl;
	}
	std::cout << "Scope:         " << lic.scope << std::endl;
	std::cout << "Issued:        " << lic.issued_at << std::endl;
	std::cout << "Expires:       " << lic.expires_at << std::endl;
	std::cout << "Status:        " << lic.status << std::endl;
	if (!lic.anchor_tx.empty()) {
		std::cout << "Anchor TX:     " << lic.anchor_tx << std::endl;
		std::cout << "Anchor RPC:    " << lic.anchor_rpc << std::endl;
	}

	// Show signatures
	bool	sigs_ok = license_verify_signatures(id);
	std::cout << "Signatures:    " << (sigs_ok ? "valid" : "INVALID or missing") << std::endl;

	return 0;
}

int license_cmd_anchor (int argc, const char** argv)
{
	const char*	rpc_url = 0;
	const char*	from_address = 0;
	Options_list	options;
	options.push_back(Option_def("--rpc-url", &rpc_url));
	options.push_back(Option_def("--from", &from_address));

	int	argi = parse_options(options, argc, argv);
	if (argc - argi != 1) {
		help_license_anchor(std::clog);
		return 2;
	}

	std::string	id = argv[argi];

	if (!rpc_url) {
		std::clog << "Error: --rpc-url is required." << std::endl;
		return 2;
	}
	if (!from_address) {
		std::clog << "Error: --from is required." << std::endl;
		return 2;
	}

	License	lic;
	try {
		lic = license_load(id);
	} catch (const Error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	std::string	hash = license_hash(lic);
	std::cout << "License hash:  " << hash << std::endl;
	std::cout << "Anchoring to:  " << rpc_url << std::endl;
	std::cout << "From:          " << from_address << std::endl;

	std::vector<std::string>	cmd;
	cmd.push_back("cast");
	cmd.push_back("send");
	cmd.push_back("--rpc-url");
	cmd.push_back(rpc_url);
	cmd.push_back("--account");
	cmd.push_back(from_address);
	cmd.push_back(from_address);
	cmd.push_back("0x" + hash);

	std::stringstream	output;
	if (!successful_exit(exec_command(cmd, output))) {
		std::clog << "Error: failed to send on-chain anchor transaction." << std::endl;
		return 1;
	}

	// Parse tx hash from cast output
	std::string	tx_hash;
	std::string	line;
	while (std::getline(output, line)) {
		if (line.find("transactionHash") != std::string::npos) {
			size_t	pos = line.find("0x");
			if (pos != std::string::npos) {
				tx_hash = line.substr(pos);
				while (!tx_hash.empty() && (tx_hash.back() == '\n' || tx_hash.back() == '\r' || tx_hash.back() == ' ')) {
					tx_hash.pop_back();
				}
			}
		}
	}

	if (tx_hash.empty()) {
		output.clear();
		output.seekg(0);
		std::string	raw = output.str();
		while (!raw.empty() && (raw.back() == '\n' || raw.back() == '\r' || raw.back() == ' ')) {
			raw.pop_back();
		}
		if (raw.size() >= 66 && raw.find("0x") != std::string::npos) {
			size_t	pos = raw.find("0x");
			tx_hash = raw.substr(pos, 66);
		}
	}

	if (tx_hash.empty()) {
		std::clog << "Warning: transaction sent but hash could not be parsed." << std::endl;
		tx_hash = "unknown";
	}

	std::cout << "Transaction:   " << tx_hash << std::endl;

	// Update license with anchor info
	lic.anchor_tx = tx_hash;
	lic.anchor_rpc = rpc_url;

	try {
		license_save(lic);
	} catch (const Error& e) {
		std::clog << "Error saving license: " << e.message << std::endl;
		return 1;
	}

	std::cout << "Anchor published successfully." << std::endl;
	return 0;
}

int license_cmd_import (int argc, const char** argv)
{
	Options_list	options;

	int	argi = parse_options(options, argc, argv);
	if (argc - argi != 1) {
		help_license_import(std::clog);
		return 2;
	}

	std::string	filename = argv[argi];

	std::ifstream	in(filename.c_str());
	if (!in) {
		std::clog << "Error: could not open " << filename << std::endl;
		return 1;
	}

	std::stringstream	buf;
	buf << in.rdbuf();
	std::string		data = buf.str();
	in.close();

	License	lic;
	try {
		lic = license_deserialize(data);
		license_save(lic);
	} catch (const Error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	std::cout << "License imported: " << lic.id << std::endl;
	return 0;
}

int license_cmd_export (int argc, const char** argv)
{
	Options_list	options;

	int	argi = parse_options(options, argc, argv);
	if (argc - argi < 1 || argc - argi > 2) {
		help_license_export(std::clog);
		return 2;
	}

	std::string	id = argv[argi];
	std::string	filename;
	if (argc - argi == 2) {
		filename = argv[argi + 1];
	} else {
		filename = id + ".license";
	}

	License	lic;
	try {
		lic = license_load(id);
	} catch (const Error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	std::string	data;
	try {
		data = license_serialize(lic);
	} catch (const Error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	std::ofstream	out(filename.c_str());
	if (!out) {
		std::clog << "Error: could not write " << filename << std::endl;
		return 1;
	}
	out << data;
	out.close();

	std::cout << "License exported to " << filename << std::endl;
	return 0;
}

int license_cmd_check (int argc, const char** argv)
{
	const char*	operation = 0;
	Options_list	options;
	options.push_back(Option_def("--operation", &operation));

	int	argi = parse_options(options, argc, argv);
	if (argc - argi != 0) {
		help_license_check(std::clog);
		return 2;
	}

	std::string	op = operation ? operation : "*";

	int	result = license_check(op);
	if (result == 0) {
		std::cout << "License valid for operation: " << op << std::endl;
	} else {
		std::cout << "No valid license for operation: " << op << std::endl;
	}

	return result;
}

int license_cmd_serve (int argc, const char** argv)
{
	const char*	port_str = 0;
	const char*	rpc_url = 0;
	Options_list	options;
	options.push_back(Option_def("--port", &port_str));
	options.push_back(Option_def("--rpc-url", &rpc_url));

	int	argi = parse_options(options, argc, argv);
	if (argc - argi != 0) {
		help_license_serve(std::clog);
		return 2;
	}

	if (!rpc_url) {
		std::clog << "Error: --rpc-url is required." << std::endl;
		return 2;
	}

	int	port = LICENSE_SERVER_PORT;
	if (port_str) {
		port = std::atoi(port_str);
		if (port <= 0 || port > 65535) {
			std::clog << "Error: invalid port number: " << port_str << std::endl;
			return 2;
		}
	}

	std::cout << "Starting x402 license server on port " << port << "..." << std::endl;

	return license_server_run(port, rpc_url);
}
