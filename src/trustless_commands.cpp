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

#include "trustless_commands.hpp"
#include "trustless_config.hpp"
#include "trustless_chain.hpp"
#include "trustless_merkle.hpp"
#include "trustless_rpc.hpp"
#include "trustless_zk.hpp"
#include "trustless_migrate.hpp"
#include "license.hpp"
#include "commands.hpp"
#include "crypto.hpp"
#include "util.hpp"
#include "parse_options.hpp"
#include "git-crypt.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <cstring>
#include <cstdlib>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>

extern const char* argv0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string get_repo_root ()
{
	std::vector<std::string> cmd;
	cmd.push_back("git");
	cmd.push_back("rev-parse");
	cmd.push_back("--show-toplevel");
	std::stringstream out;
	int s = exec_command(cmd, out);
	if (!successful_exit(s)) throw Error("Not a git repository");
	std::string root = out.str();
	while (!root.empty() && (root.back() == '\n' || root.back() == '\r'))
		root.pop_back();
	return root;
}

static std::string unix_to_iso8601 (uint64_t ts)
{
	time_t t = static_cast<time_t>(ts);
	struct tm tm;
	gmtime_r(&t, &tm);
	char buf[32];
	strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
	return std::string(buf);
}

static uint64_t iso8601_to_unix (const std::string& ts)
{
	struct tm tm;
	std::memset(&tm, 0, sizeof(tm));
	if (ts.size() >= 19) {
		tm.tm_year = std::atoi(ts.substr(0, 4).c_str()) - 1900;
		tm.tm_mon = std::atoi(ts.substr(5, 2).c_str()) - 1;
		tm.tm_mday = std::atoi(ts.substr(8, 2).c_str());
		tm.tm_hour = std::atoi(ts.substr(11, 2).c_str());
		tm.tm_min = std::atoi(ts.substr(14, 2).c_str());
		tm.tm_sec = std::atoi(ts.substr(17, 2).c_str());
	}
	return static_cast<uint64_t>(timegm(&tm));
}

static uint64_t parse_duration_to_unix (const std::string& dur)
{
	uint64_t now = static_cast<uint64_t>(std::time(NULL));
	if (dur.empty()) return now + 365 * 86400;  // default: 1 year

	// If it looks like ISO 8601, parse it directly
	if (dur.find('T') != std::string::npos || dur.find('-') != std::string::npos) {
		return iso8601_to_unix(dur);
	}

	// Parse duration: 90d, 1y, 6m, etc.
	int num = std::atoi(dur.c_str());
	char unit = dur[dur.size() - 1];
	switch (unit) {
	case 'd': return now + num * 86400;
	case 'm': return now + num * 30 * 86400;
	case 'y': return now + num * 365 * 86400;
	default: return now + num * 86400;  // assume days
	}
}

static std::string pad_id_hex (const std::string& id)
{
	std::string hex = id;
	// Ensure 0x prefix
	if (hex.size() < 2 || hex.substr(0, 2) != "0x") {
		hex = "0x" + hex;
	}
	// Pad to 34 chars (0x + 32 hex = 16 bytes)
	while (hex.size() < 34) {
		hex += "00";
	}
	return hex;
}

static std::string merkle_data_path ()
{
	return trustless_data_dir() + "/merkle.dat";
}

static MerkleTree load_or_create_merkle ()
{
	MerkleTree tree;
	std::string path = merkle_data_path();
	struct stat st;
	if (stat(path.c_str(), &st) == 0) {
		tree.load(path);
	}
	return tree;
}

// ---------------------------------------------------------------------------
// Help functions
// ---------------------------------------------------------------------------

void help_trustless_init (std::ostream& out)
{
	out << "Usage: " << argv0 << " init [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --rpc-url URL               EVM RPC endpoint" << std::endl;
	out << "    --registry ADDRESS           LicenseRegistry contract address" << std::endl;
	out << "    --audit ADDRESS              MerkleAudit contract address" << std::endl;
	out << "    --chain-id ID                EVM chain ID" << std::endl;
	out << "    --from ADDRESS               Sender address" << std::endl;
	out << "    --deploy                     Deploy new contracts instead of connecting" << std::endl;
	out << std::endl;
	out << "Connect to existing contracts or deploy new ones." << std::endl;
	out << "Configuration is stored in git config (trustless.* keys)." << std::endl;
}

void help_trustless_deploy (std::ostream& out)
{
	out << "Usage: " << argv0 << " deploy [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --rpc-url URL               EVM RPC endpoint" << std::endl;
	out << "    --contracts-dir DIR          Path to contracts directory" << std::endl;
	out << std::endl;
	out << "Deploy fresh LicenseRegistry and MerkleAudit contracts." << std::endl;
}

void help_trustless_issue (std::ostream& out)
{
	out << "Usage: " << argv0 << " issue --to FINGERPRINT --scope OPERATIONS --expires DURATION" << std::endl;
	out << std::endl;
	out << "    --to FINGERPRINT             Licensee SSH fingerprint" << std::endl;
	out << "    --wallet ADDRESS             Licensee wallet address (optional)" << std::endl;
	out << "    --scope OPERATIONS           Comma-separated operations or '*'" << std::endl;
	out << "    --expires DURATION           Duration (90d, 1y) or ISO 8601 date" << std::endl;
	out << "    --json                       Output as JSON" << std::endl;
	out << std::endl;
	out << "Issue a license on-chain. The licensee fingerprint and scope are stored" << std::endl;
	out << "as keccak256 hashes for privacy." << std::endl;
}

void help_trustless_verify (std::ostream& out)
{
	out << "Usage: " << argv0 << " verify LICENSE_ID" << std::endl;
	out << std::endl;
	out << "    --json                       Output as JSON" << std::endl;
	out << std::endl;
	out << "Verify a license from the on-chain registry." << std::endl;
	out << "Uses multi-RPC consensus if configured." << std::endl;
}

void help_trustless_revoke (std::ostream& out)
{
	out << "Usage: " << argv0 << " revoke LICENSE_ID" << std::endl;
	out << std::endl;
	out << "Revoke a license on-chain. Only callable by issuers." << std::endl;
}

void help_trustless_list (std::ostream& out)
{
	out << "Usage: " << argv0 << " list [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --all                        Include revoked licenses" << std::endl;
	out << "    --json                       Output as JSON" << std::endl;
	out << std::endl;
	out << "List licenses from the on-chain registry." << std::endl;
}

void help_trustless_show (std::ostream& out)
{
	out << "Usage: " << argv0 << " show LICENSE_ID" << std::endl;
	out << std::endl;
	out << "    --json                       Output as JSON" << std::endl;
	out << std::endl;
	out << "Show details of a license from the on-chain registry." << std::endl;
}

void help_trustless_check (std::ostream& out)
{
	out << "Usage: " << argv0 << " check [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --operation OP               Operation to check authorization for" << std::endl;
	out << "    --fingerprint FP             Fingerprint to check (default: current user)" << std::endl;
	out << std::endl;
	out << "Check if the current user has a valid on-chain license." << std::endl;
}

void help_trustless_export (std::ostream& out)
{
	out << "Usage: " << argv0 << " export LICENSE_ID [FILE]" << std::endl;
	out << std::endl;
	out << "Export an on-chain license to a file." << std::endl;
	out << "If FILE is omitted, writes to stdout." << std::endl;
}

void help_trustless_import (std::ostream& out)
{
	out << "Usage: " << argv0 << " import FILE" << std::endl;
	out << std::endl;
	out << "Import a license file and register it on-chain if not already present." << std::endl;
}

void help_trustless_migrate (std::ostream& out)
{
	out << "Usage: " << argv0 << " migrate [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --all                        Migrate all licenses" << std::endl;
	out << "    --id LICENSE_ID              Migrate a specific license" << std::endl;
	out << "    --dry-run                    Show what would be migrated" << std::endl;
	out << std::endl;
	out << "Migrate git-crypt-license data to on-chain registry." << std::endl;
}

void help_trustless_prove (std::ostream& out)
{
	out << "Usage: " << argv0 << " prove --license-id ID --operation OP" << std::endl;
	out << std::endl;
	out << "Generate a zero-knowledge proof of valid license ownership." << std::endl;
	out << "Phase 2 feature — not available in v0.1.0." << std::endl;
}

void help_trustless_verify_proof (std::ostream& out)
{
	out << "Usage: " << argv0 << " verify-proof --proof FILE" << std::endl;
	out << std::endl;
	out << "Verify a zero-knowledge proof on-chain." << std::endl;
	out << "Phase 2 feature — not available in v0.1.0." << std::endl;
}

void help_trustless_audit_root (std::ostream& out)
{
	out << "Usage: " << argv0 << " audit-root" << std::endl;
	out << std::endl;
	out << "Commit the current Merkle audit root on-chain." << std::endl;
}

void help_trustless_audit_prove (std::ostream& out)
{
	out << "Usage: " << argv0 << " audit-prove --entry INDEX" << std::endl;
	out << std::endl;
	out << "    --entry INDEX                Leaf index to prove" << std::endl;
	out << "    --output FILE                Write proof to file (default: stdout)" << std::endl;
	out << std::endl;
	out << "Generate a Merkle proof for an audit entry." << std::endl;
}

void help_trustless_audit_verify (std::ostream& out)
{
	out << "Usage: " << argv0 << " audit-verify --proof FILE" << std::endl;
	out << std::endl;
	out << "    --proof FILE                 Proof file (JSON)" << std::endl;
	out << "    --leaf HASH                  Leaf hash to verify" << std::endl;
	out << "    --onchain                    Verify against on-chain root" << std::endl;
	out << std::endl;
	out << "Verify a Merkle proof against a committed root." << std::endl;
}

void help_trustless_config (std::ostream& out)
{
	out << "Usage: " << argv0 << " config" << std::endl;
	out << std::endl;
	out << "Show current trustless configuration." << std::endl;
}

void help_trustless_serve (std::ostream& out)
{
	out << "Usage: " << argv0 << " serve [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --port PORT                  Listen port (default: 8403)" << std::endl;
	out << std::endl;
	out << "Start an HTTP server backed by on-chain contract reads." << std::endl;
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

int trustless_cmd_init (int argc, const char** argv)
{
	const char* rpc_url = 0;
	const char* registry = 0;
	const char* audit_addr = 0;
	const char* chain_id = 0;
	const char* from_addr = 0;
	bool deploy = false;

	Options_list options;
	options.push_back(Option_def("--rpc-url", &rpc_url));
	options.push_back(Option_def("--registry", &registry));
	options.push_back(Option_def("--audit", &audit_addr));
	options.push_back(Option_def("--chain-id", &chain_id));
	options.push_back(Option_def("--from", &from_addr));
	options.push_back(Option_def("--deploy", &deploy));

	parse_options(options, argc, argv);

	// Create data directory
	std::string data_dir = trustless_data_dir();
	mkdir_parent(data_dir + "/dummy");

	if (deploy) {
		// Deploy new contracts
		if (!rpc_url) {
			std::clog << "Error: --rpc-url required for deployment." << std::endl;
			help_trustless_init(std::clog);
			return 2;
		}

		Trustless_config cfg;
		cfg.rpc_url = rpc_url;
		if (from_addr) cfg.from_address = from_addr;

		// Check for private key in env
		const char* pk = std::getenv("GIT_CRYPT_TRUSTLESS_PRIVATE_KEY");
		if (pk) cfg.private_key = pk;

		std::string repo_root = get_repo_root();
		std::string contracts_dir = repo_root + "/contracts";

		std::cerr << "Deploying contracts to " << rpc_url << "..." << std::endl;
		Deploy_result result = trustless_deploy_contracts(cfg, contracts_dir);

		if (result.registry_address.empty()) {
			throw Error("Deployment failed: could not determine registry address.");
		}

		// Save to git config
		trustless_git_config_set("trustless.rpc-url", rpc_url);
		trustless_git_config_set("trustless.registry-address", result.registry_address);
		if (!result.audit_address.empty()) {
			trustless_git_config_set("trustless.audit-address", result.audit_address);
		}
		if (chain_id) trustless_git_config_set("trustless.chain-id", chain_id);
		if (from_addr) trustless_git_config_set("trustless.from-address", from_addr);

		std::cout << "Contracts deployed successfully." << std::endl;
		std::cout << "  Registry: " << result.registry_address << std::endl;
		std::cout << "  Audit:    " << result.audit_address << std::endl;
	} else {
		// Connect to existing contracts
		if (!rpc_url || !registry) {
			std::clog << "Error: --rpc-url and --registry required (or use --deploy)." << std::endl;
			help_trustless_init(std::clog);
			return 2;
		}

		trustless_git_config_set("trustless.rpc-url", rpc_url);
		trustless_git_config_set("trustless.registry-address", registry);
		if (audit_addr) trustless_git_config_set("trustless.audit-address", audit_addr);
		if (chain_id) trustless_git_config_set("trustless.chain-id", chain_id);
		if (from_addr) trustless_git_config_set("trustless.from-address", from_addr);

		std::cout << "Trustless module initialized." << std::endl;
		std::cout << "  RPC:      " << rpc_url << std::endl;
		std::cout << "  Registry: " << registry << std::endl;
		if (audit_addr) std::cout << "  Audit:    " << audit_addr << std::endl;
	}

	return 0;
}

int trustless_cmd_deploy (int argc, const char** argv)
{
	const char* rpc_url = 0;
	const char* contracts_dir_opt = 0;

	Options_list options;
	options.push_back(Option_def("--rpc-url", &rpc_url));
	options.push_back(Option_def("--contracts-dir", &contracts_dir_opt));

	parse_options(options, argc, argv);

	Trustless_config cfg;
	if (rpc_url) {
		cfg.rpc_url = rpc_url;
	} else {
		cfg = trustless_config_load_partial();
		if (cfg.rpc_url.empty()) {
			std::clog << "Error: --rpc-url required." << std::endl;
			help_trustless_deploy(std::clog);
			return 2;
		}
	}

	const char* pk = std::getenv("GIT_CRYPT_TRUSTLESS_PRIVATE_KEY");
	if (pk) cfg.private_key = pk;

	std::string contracts_dir;
	if (contracts_dir_opt) {
		contracts_dir = contracts_dir_opt;
	} else {
		contracts_dir = get_repo_root() + "/contracts";
	}

	std::cerr << "Deploying contracts to " << cfg.rpc_url << "..." << std::endl;
	Deploy_result result = trustless_deploy_contracts(cfg, contracts_dir);

	std::cout << "Registry: " << result.registry_address << std::endl;
	std::cout << "Audit:    " << result.audit_address << std::endl;

	// Save addresses
	if (!result.registry_address.empty()) {
		trustless_git_config_set("trustless.registry-address", result.registry_address);
	}
	if (!result.audit_address.empty()) {
		trustless_git_config_set("trustless.audit-address", result.audit_address);
	}

	return 0;
}

int trustless_cmd_issue (int argc, const char** argv)
{
	const char* to_fingerprint = 0;
	const char* wallet = 0;
	const char* scope = 0;
	const char* expires = 0;
	bool json = false;

	Options_list options;
	options.push_back(Option_def("--to", &to_fingerprint));
	options.push_back(Option_def("--wallet", &wallet));
	options.push_back(Option_def("--scope", &scope));
	options.push_back(Option_def("--expires", &expires));
	options.push_back(Option_def("--json", &json));

	parse_options(options, argc, argv);

	if (!to_fingerprint || !scope) {
		std::clog << "Error: --to and --scope are required." << std::endl;
		help_trustless_issue(std::clog);
		return 2;
	}

	Trustless_config cfg = trustless_config_load();

	// Generate license ID
	std::string id = license_generate_id();
	std::string id_hex = pad_id_hex(id);

	// Compute hashes
	std::string licensee_hash = trustless_keccak256(to_fingerprint);
	std::string scope_hash = trustless_keccak256(scope);

	// Timestamps
	uint64_t issued_at = static_cast<uint64_t>(std::time(NULL));
	uint64_t expires_at = expires ? parse_duration_to_unix(expires) : issued_at + 365 * 86400;

	// Content hash: hash of all license fields concatenated
	std::string content_str = id + std::string(to_fingerprint) + std::string(scope);
	std::string content_hash = trustless_keccak256(content_str);

	std::string wallet_addr = wallet ? wallet : "";

	// Issue on-chain
	std::string tx_hash = trustless_chain_issue(cfg, id_hex, licensee_hash,
		wallet_addr, scope_hash, issued_at, expires_at, content_hash);

	// Append to local Merkle tree
	MerkleTree tree = load_or_create_merkle();
	tree.append(content_hash);
	tree.save(merkle_data_path());

	if (json) {
		std::cout << "{" << std::endl;
		std::cout << "  \"id\": \"" << id << "\"," << std::endl;
		std::cout << "  \"tx_hash\": \"" << tx_hash << "\"," << std::endl;
		std::cout << "  \"issued_at\": \"" << unix_to_iso8601(issued_at) << "\"," << std::endl;
		std::cout << "  \"expires_at\": \"" << unix_to_iso8601(expires_at) << "\"," << std::endl;
		std::cout << "  \"status\": \"active\"" << std::endl;
		std::cout << "}" << std::endl;
	} else {
		std::cout << "License issued on-chain." << std::endl;
		std::cout << "  ID:         " << id << std::endl;
		std::cout << "  TX:         " << tx_hash << std::endl;
		std::cout << "  Issued:     " << unix_to_iso8601(issued_at) << std::endl;
		std::cout << "  Expires:    " << unix_to_iso8601(expires_at) << std::endl;
	}

	return 0;
}

int trustless_cmd_verify (int argc, const char** argv)
{
	bool json = false;
	Options_list options;
	options.push_back(Option_def("--json", &json));

	int argi = parse_options(options, argc, argv);
	if (argc - argi != 1) {
		help_trustless_verify(std::clog);
		return 2;
	}

	std::string license_id = argv[argi];
	std::string id_hex = pad_id_hex(license_id);

	Trustless_config cfg = trustless_config_load();

	// Use multi-RPC consensus if configured
	if (trustless_rpc_is_multi(cfg)) {
		Rpc_verify_result result = trustless_rpc_consensus_verify(cfg, id_hex);

		if (!result.consensus_reached) {
			std::cerr << "Error: Multi-RPC consensus failed." << std::endl;
			return 1;
		}

		if (json) {
			std::cout << "{\"valid\": " << (result.valid ? "true" : "false")
				  << ", \"status\": " << static_cast<int>(result.status)
				  << ", \"expires_at\": " << result.expires_at
				  << ", \"consensus\": " << result.agreeing_count << "/" << result.total_count
				  << "}" << std::endl;
		} else {
			std::cout << "License " << license_id << ": "
				  << (result.valid ? "VALID" : "INVALID") << std::endl;
			std::cout << "  Status:    " << (result.status == 0 ? "active" : "revoked") << std::endl;
			std::cout << "  Expires:   " << unix_to_iso8601(result.expires_at) << std::endl;
			std::cout << "  Consensus: " << result.agreeing_count << "/" << result.total_count << " RPCs" << std::endl;
		}

		return result.valid ? 0 : 1;
	}

	Chain_verify_result result = trustless_chain_verify(cfg, id_hex);

	if (json) {
		std::cout << "{\"valid\": " << (result.valid ? "true" : "false")
			  << ", \"status\": " << static_cast<int>(result.status)
			  << ", \"expires_at\": " << result.expires_at
			  << "}" << std::endl;
	} else {
		std::cout << "License " << license_id << ": "
			  << (result.valid ? "VALID" : "INVALID") << std::endl;
		std::cout << "  Status:  " << (result.status == 0 ? "active" : "revoked") << std::endl;
		std::cout << "  Expires: " << unix_to_iso8601(result.expires_at) << std::endl;
	}

	return result.valid ? 0 : 1;
}

int trustless_cmd_revoke (int argc, const char** argv)
{
	Options_list options;
	int argi = parse_options(options, argc, argv);

	if (argc - argi != 1) {
		help_trustless_revoke(std::clog);
		return 2;
	}

	std::string license_id = argv[argi];
	std::string id_hex = pad_id_hex(license_id);

	Trustless_config cfg = trustless_config_load();

	std::string tx_hash = trustless_chain_revoke(cfg, id_hex);

	// Append revocation event to Merkle tree
	std::string revoke_hash = trustless_keccak256("revoke:" + license_id);
	MerkleTree tree = load_or_create_merkle();
	tree.append(revoke_hash);
	tree.save(merkle_data_path());

	std::cout << "License " << license_id << " revoked." << std::endl;
	std::cout << "  TX: " << tx_hash << std::endl;

	return 0;
}

int trustless_cmd_list (int argc, const char** argv)
{
	bool all = false;
	bool json = false;

	Options_list options;
	options.push_back(Option_def("--all", &all));
	options.push_back(Option_def("--json", &json));

	parse_options(options, argc, argv);

	Trustless_config cfg = trustless_config_load();

	uint64_t count = trustless_chain_license_count(cfg);

	if (count == 0) {
		if (json) {
			std::cout << "[]" << std::endl;
		} else {
			std::cout << "No licenses found." << std::endl;
		}
		return 0;
	}

	// We need to iterate through licenses. Since the contract uses bytes16 keys,
	// we read the license count and attempt to read licenses by querying known IDs.
	// For a full list, we'd need an enumerable set or event log query.
	// For now, output the count and suggest using `show` for specific IDs.
	if (json) {
		std::cout << "{\"license_count\": " << count << "}" << std::endl;
	} else {
		std::cout << "On-chain license count: " << count << std::endl;
		if (!all) {
			std::cout << "(Use 'show LICENSE_ID' to view specific licenses)" << std::endl;
		}
	}

	return 0;
}

int trustless_cmd_show (int argc, const char** argv)
{
	bool json = false;
	Options_list options;
	options.push_back(Option_def("--json", &json));

	int argi = parse_options(options, argc, argv);
	if (argc - argi != 1) {
		help_trustless_show(std::clog);
		return 2;
	}

	std::string license_id = argv[argi];
	std::string id_hex = pad_id_hex(license_id);

	Trustless_config cfg = trustless_config_load();

	Chain_license lic = trustless_chain_get_license(cfg, id_hex);

	if (json) {
		std::cout << "{" << std::endl;
		std::cout << "  \"id\": \"" << lic.id << "\"," << std::endl;
		std::cout << "  \"licensee_hash\": \"" << lic.licensee_hash << "\"," << std::endl;
		std::cout << "  \"licensee_wallet\": \"" << lic.licensee_wallet << "\"," << std::endl;
		std::cout << "  \"scope_hash\": \"" << lic.scope_hash << "\"," << std::endl;
		std::cout << "  \"issued_at\": \"" << unix_to_iso8601(lic.issued_at) << "\"," << std::endl;
		std::cout << "  \"expires_at\": \"" << unix_to_iso8601(lic.expires_at) << "\"," << std::endl;
		std::cout << "  \"status\": \"" << (lic.status == 0 ? "active" : "revoked") << "\"," << std::endl;
		std::cout << "  \"content_hash\": \"" << lic.content_hash << "\"" << std::endl;
		std::cout << "}" << std::endl;
	} else {
		std::cout << "License " << license_id << std::endl;
		std::cout << "  Licensee Hash:  " << lic.licensee_hash << std::endl;
		std::cout << "  Wallet:         " << lic.licensee_wallet << std::endl;
		std::cout << "  Scope Hash:     " << lic.scope_hash << std::endl;
		std::cout << "  Issued:         " << unix_to_iso8601(lic.issued_at) << std::endl;
		std::cout << "  Expires:        " << unix_to_iso8601(lic.expires_at) << std::endl;
		std::cout << "  Status:         " << (lic.status == 0 ? "active" : "revoked") << std::endl;
		std::cout << "  Content Hash:   " << lic.content_hash << std::endl;
	}

	return 0;
}

int trustless_cmd_check (int argc, const char** argv)
{
	const char* operation = 0;
	const char* fingerprint = 0;

	Options_list options;
	options.push_back(Option_def("--operation", &operation));
	options.push_back(Option_def("--fingerprint", &fingerprint));

	parse_options(options, argc, argv);

	if (!operation) operation = "unlock";

	Trustless_config cfg = trustless_config_load();

	// Get current user's SSH fingerprint if not specified
	std::string fp;
	if (fingerprint) {
		fp = fingerprint;
	} else {
		std::vector<std::string> cmd;
		cmd.push_back("ssh-add");
		cmd.push_back("-l");
		std::stringstream out;
		int s = exec_command(cmd, out);
		if (successful_exit(s)) {
			std::string line = out.str();
			// Extract first fingerprint (second field)
			size_t start = line.find(' ');
			if (start != std::string::npos) {
				start++;
				size_t end = line.find(' ', start);
				if (end != std::string::npos) {
					fp = line.substr(start, end - start);
				}
			}
		}
	}

	if (fp.empty()) {
		std::cerr << "Error: Could not determine SSH fingerprint. Use --fingerprint." << std::endl;
		return 1;
	}

	// Hash the fingerprint and scope to match on-chain format
	std::string fp_hash = trustless_keccak256(fp);
	std::string scope_hash = trustless_keccak256(operation);

	// We need to check if any active license matches this fingerprint+scope.
	// Since the contract stores hashes, we verify by querying known license IDs
	// or checking if the user has a local license file with an on-chain ID.
	// For v0.1.0, check local license data for IDs, then verify each on-chain.

	std::vector<std::string> ids = license_list_ids();
	for (size_t i = 0; i < ids.size(); ++i) {
		try {
			std::string id_hex = pad_id_hex(ids[i]);
			Chain_verify_result result = trustless_chain_verify(cfg, id_hex);
			if (result.valid) {
				std::cout << "License check passed (ID: " << ids[i] << ")" << std::endl;
				return 0;
			}
		} catch (...) {
			// Skip licenses that can't be verified
		}
	}

	std::cerr << "No valid on-chain license found for operation '" << operation << "'." << std::endl;
	return 1;
}

int trustless_cmd_export (int argc, const char** argv)
{
	Options_list options;
	int argi = parse_options(options, argc, argv);

	if (argc - argi < 1) {
		help_trustless_export(std::clog);
		return 2;
	}

	std::string license_id = argv[argi];
	const char* output_file = (argc - argi >= 2) ? argv[argi + 1] : NULL;

	std::string id_hex = pad_id_hex(license_id);
	Trustless_config cfg = trustless_config_load();

	Chain_license lic = trustless_chain_get_license(cfg, id_hex);

	// Serialize to portable format
	std::stringstream ss;
	ss << "# git-crypt-trustless license export" << std::endl;
	ss << "id\t" << license_id << std::endl;
	ss << "licensee_hash\t" << lic.licensee_hash << std::endl;
	ss << "licensee_wallet\t" << lic.licensee_wallet << std::endl;
	ss << "scope_hash\t" << lic.scope_hash << std::endl;
	ss << "issued_at\t" << unix_to_iso8601(lic.issued_at) << std::endl;
	ss << "expires_at\t" << unix_to_iso8601(lic.expires_at) << std::endl;
	ss << "status\t" << (lic.status == 0 ? "active" : "revoked") << std::endl;
	ss << "content_hash\t" << lic.content_hash << std::endl;
	ss << "registry\t" << cfg.registry_address << std::endl;
	ss << "chain_rpc\t" << cfg.rpc_url << std::endl;

	if (output_file) {
		std::ofstream out(output_file);
		if (!out) throw Error(std::string("Cannot write to ") + output_file);
		out << ss.str();
		std::cerr << "License exported to " << output_file << std::endl;
	} else {
		std::cout << ss.str();
	}

	return 0;
}

int trustless_cmd_import (int argc, const char** argv)
{
	Options_list options;
	int argi = parse_options(options, argc, argv);

	if (argc - argi != 1) {
		help_trustless_import(std::clog);
		return 2;
	}

	std::string input_file = argv[argi];
	std::ifstream in(input_file.c_str());
	if (!in) throw Error("Cannot open " + input_file);

	// Parse license file
	std::string id, licensee_hash, wallet, scope_hash, content_hash;
	uint64_t issued_at = 0, expires_at = 0;
	std::string line;
	while (std::getline(in, line)) {
		if (line.empty() || line[0] == '#') continue;
		size_t tab = line.find('\t');
		if (tab == std::string::npos) continue;
		std::string key = line.substr(0, tab);
		std::string val = line.substr(tab + 1);
		if (key == "id") id = val;
		else if (key == "licensee_hash") licensee_hash = val;
		else if (key == "licensee_wallet") wallet = val;
		else if (key == "scope_hash") scope_hash = val;
		else if (key == "issued_at") issued_at = iso8601_to_unix(val);
		else if (key == "expires_at") expires_at = iso8601_to_unix(val);
		else if (key == "content_hash") content_hash = val;
	}

	if (id.empty() || content_hash.empty()) {
		throw Error("Invalid license file: missing required fields.");
	}

	Trustless_config cfg = trustless_config_load();
	std::string id_hex = pad_id_hex(id);

	// Check if already on-chain
	try {
		Chain_verify_result existing = trustless_chain_verify(cfg, id_hex);
		if (existing.expires_at > 0) {
			std::cout << "License " << id << " already exists on-chain." << std::endl;
			return 0;
		}
	} catch (...) {
		// Not found on-chain, proceed with import
	}

	// Register on-chain
	std::string tx_hash = trustless_chain_issue(cfg, id_hex, licensee_hash,
		wallet, scope_hash, issued_at, expires_at, content_hash);

	std::cout << "License " << id << " imported and registered on-chain." << std::endl;
	std::cout << "  TX: " << tx_hash << std::endl;

	return 0;
}

int trustless_cmd_migrate (int argc, const char** argv)
{
	bool all = false;
	bool dry_run = false;
	const char* single_id = 0;

	Options_list options;
	options.push_back(Option_def("--all", &all));
	options.push_back(Option_def("--dry-run", &dry_run));
	options.push_back(Option_def("--id", &single_id));

	parse_options(options, argc, argv);

	if (!all && !single_id) {
		std::clog << "Error: --all or --id required." << std::endl;
		help_trustless_migrate(std::clog);
		return 2;
	}

	if (!trustless_has_license_data()) {
		std::cerr << "No git-crypt-license data found to migrate." << std::endl;
		return 1;
	}

	Trustless_config cfg = trustless_config_load();

	if (single_id) {
		if (dry_run) {
			std::cout << "Would migrate license: " << single_id << std::endl;
			return 0;
		}
		Migration_result result = trustless_migrate_one(cfg, single_id);
		if (result.success) {
			std::cout << "Migrated " << result.license_id << " (TX: " << result.tx_hash << ")" << std::endl;
		} else {
			std::cerr << "Failed to migrate " << result.license_id << ": " << result.error << std::endl;
			return 1;
		}
	} else {
		std::vector<std::string> candidates = trustless_migration_candidates();
		if (candidates.empty()) {
			std::cout << "No licenses to migrate." << std::endl;
			return 0;
		}

		if (dry_run) {
			std::cout << "Would migrate " << candidates.size() << " licenses:" << std::endl;
			for (size_t i = 0; i < candidates.size(); ++i) {
				std::cout << "  " << candidates[i] << std::endl;
			}
			return 0;
		}

		std::vector<Migration_result> results = trustless_migrate_all(cfg);
		int success_count = 0;
		int fail_count = 0;
		for (size_t i = 0; i < results.size(); ++i) {
			if (results[i].success) {
				std::cout << "  OK: " << results[i].license_id << " (TX: " << results[i].tx_hash << ")" << std::endl;
				success_count++;
			} else {
				std::cerr << "  FAIL: " << results[i].license_id << ": " << results[i].error << std::endl;
				fail_count++;
			}
		}
		std::cout << "Migration complete: " << success_count << " success, " << fail_count << " failed." << std::endl;
		return fail_count > 0 ? 1 : 0;
	}

	return 0;
}

int trustless_cmd_prove (int argc, const char** argv)
{
	std::cerr << "ZK proofs are not available in v0.1.0 (Phase 2 feature)." << std::endl;
	std::cerr << "See doc/trustless-guide.md section 6 for the planned implementation." << std::endl;
	return 1;
}

int trustless_cmd_verify_proof (int argc, const char** argv)
{
	std::cerr << "ZK proof verification is not available in v0.1.0 (Phase 2 feature)." << std::endl;
	std::cerr << "See doc/trustless-guide.md section 6 for the planned implementation." << std::endl;
	return 1;
}

int trustless_cmd_audit_root (int argc, const char** argv)
{
	Options_list options;
	parse_options(options, argc, argv);

	Trustless_config cfg = trustless_config_load();

	MerkleTree tree = load_or_create_merkle();
	if (tree.leaf_count() == 0) {
		std::cerr << "No audit entries to commit." << std::endl;
		return 1;
	}

	std::string root = tree.root();
	std::string tx_hash = trustless_chain_commit_root(cfg, root, tree.leaf_count());

	std::cout << "Merkle root committed on-chain." << std::endl;
	std::cout << "  Root:       " << root << std::endl;
	std::cout << "  Leaves:     " << tree.leaf_count() << std::endl;
	std::cout << "  TX:         " << tx_hash << std::endl;

	return 0;
}

int trustless_cmd_audit_prove (int argc, const char** argv)
{
	const char* entry_str = 0;
	const char* output_file = 0;

	Options_list options;
	options.push_back(Option_def("--entry", &entry_str));
	options.push_back(Option_def("--output", &output_file));

	parse_options(options, argc, argv);

	if (!entry_str) {
		help_trustless_audit_prove(std::clog);
		return 2;
	}

	uint32_t entry_index = static_cast<uint32_t>(std::atoi(entry_str));

	MerkleTree tree = load_or_create_merkle();
	if (entry_index >= tree.leaf_count()) {
		std::cerr << "Entry index " << entry_index << " out of range (0-" << (tree.leaf_count() - 1) << ")." << std::endl;
		return 1;
	}

	MerkleProof proof = tree.proof(entry_index);
	std::string json = merkle_proof_to_json(proof);

	// Also include the leaf hash and root for convenience
	std::string leaf = tree.leaf_at(entry_index);
	std::string root = tree.root();

	std::stringstream full_json;
	full_json << "{" << std::endl;
	full_json << "  \"leaf\": \"" << leaf << "\"," << std::endl;
	full_json << "  \"root\": \"" << root << "\"," << std::endl;
	full_json << "  \"proof\": " << json;
	full_json << "}" << std::endl;

	if (output_file) {
		std::ofstream out(output_file);
		if (!out) throw Error(std::string("Cannot write to ") + output_file);
		out << full_json.str();
		std::cerr << "Proof written to " << output_file << std::endl;
	} else {
		std::cout << full_json.str();
	}

	return 0;
}

int trustless_cmd_audit_verify (int argc, const char** argv)
{
	const char* proof_file = 0;
	const char* leaf_hash = 0;
	bool onchain = false;

	Options_list options;
	options.push_back(Option_def("--proof", &proof_file));
	options.push_back(Option_def("--leaf", &leaf_hash));
	options.push_back(Option_def("--onchain", &onchain));

	parse_options(options, argc, argv);

	if (!proof_file) {
		help_trustless_audit_verify(std::clog);
		return 2;
	}

	// Read proof file
	std::ifstream in(proof_file);
	if (!in) throw Error(std::string("Cannot open proof file: ") + proof_file);
	std::stringstream buf;
	buf << in.rdbuf();
	std::string json_content = buf.str();

	// Parse the proof
	MerkleProof proof = merkle_proof_from_json(json_content);

	// Extract leaf and root from the wrapper JSON
	std::string leaf;
	std::string root;

	size_t pos = json_content.find("\"leaf\"");
	if (pos != std::string::npos) {
		size_t start = json_content.find("\"0x", pos);
		size_t end = json_content.find("\"", start + 1);
		if (start != std::string::npos && end != std::string::npos) {
			leaf = json_content.substr(start + 1, end - start - 1);
		}
	}

	pos = json_content.find("\"root\"");
	if (pos != std::string::npos) {
		size_t start = json_content.find("\"0x", pos);
		size_t end = json_content.find("\"", start + 1);
		if (start != std::string::npos && end != std::string::npos) {
			root = json_content.substr(start + 1, end - start - 1);
		}
	}

	// Override with command-line leaf if provided
	if (leaf_hash) leaf = leaf_hash;

	if (leaf.empty()) {
		std::cerr << "Error: No leaf hash found in proof file or --leaf." << std::endl;
		return 2;
	}

	if (onchain) {
		// Verify against on-chain root
		Trustless_config cfg = trustless_config_load();
		Chain_root chain_root = trustless_chain_latest_root(cfg);

		bool valid = MerkleTree::verify(leaf, proof, chain_root.root);
		if (valid) {
			std::cout << "Merkle proof VALID (verified against on-chain root)." << std::endl;
			std::cout << "  Root:     " << chain_root.root << std::endl;
			std::cout << "  Leaves:   " << chain_root.leaf_count << std::endl;
			return 0;
		} else {
			std::cout << "Merkle proof INVALID." << std::endl;
			return 1;
		}
	} else {
		// Verify against local root
		if (root.empty()) {
			MerkleTree tree = load_or_create_merkle();
			root = tree.root();
		}

		bool valid = MerkleTree::verify(leaf, proof, root);
		if (valid) {
			std::cout << "Merkle proof VALID." << std::endl;
			std::cout << "  Root: " << root << std::endl;
			return 0;
		} else {
			std::cout << "Merkle proof INVALID." << std::endl;
			return 1;
		}
	}
}

int trustless_cmd_config (int argc, const char** argv)
{
	Trustless_config cfg = trustless_config_load_partial();

	std::cout << "Trustless Configuration:" << std::endl;
	std::cout << "  RPC URL:          " << (cfg.rpc_url.empty() ? "(not set)" : cfg.rpc_url) << std::endl;
	std::cout << "  Chain ID:         " << (cfg.chain_id.empty() ? "(not set)" : cfg.chain_id) << std::endl;
	std::cout << "  Registry:         " << (cfg.registry_address.empty() ? "(not set)" : cfg.registry_address) << std::endl;
	std::cout << "  Audit:            " << (cfg.audit_address.empty() ? "(not set)" : cfg.audit_address) << std::endl;
	std::cout << "  From:             " << (cfg.from_address.empty() ? "(not set)" : cfg.from_address) << std::endl;
	std::cout << "  Private Key:      " << (cfg.private_key.empty() ? "(not set)" : "(set via env)") << std::endl;

	if (!cfg.rpc_urls.empty() && cfg.rpc_urls.size() > 1) {
		std::cout << "  Multi-RPC:        " << cfg.rpc_urls.size() << " endpoints" << std::endl;
		for (size_t i = 0; i < cfg.rpc_urls.size(); ++i) {
			std::cout << "    [" << i << "] " << cfg.rpc_urls[i] << std::endl;
		}
		std::cout << "  RPC Threshold:    " << cfg.rpc_threshold << std::endl;
	}

	// Show local state
	std::string data_dir = trustless_data_dir();
	struct stat st;
	bool has_merkle = (stat(merkle_data_path().c_str(), &st) == 0);

	std::cout << std::endl;
	std::cout << "Local State:" << std::endl;
	std::cout << "  Data Dir:         " << data_dir << std::endl;
	std::cout << "  Merkle Tree:      " << (has_merkle ? "yes" : "no") << std::endl;
	if (has_merkle) {
		MerkleTree tree;
		tree.load(merkle_data_path());
		std::cout << "  Merkle Leaves:    " << tree.leaf_count() << std::endl;
		if (tree.leaf_count() > 0) {
			std::cout << "  Merkle Root:      " << tree.root() << std::endl;
		}
	}

	std::cout << "  ZK Available:     " << (trustless_zk_available() ? "yes" : "no") << std::endl;

	return 0;
}

// ---------------------------------------------------------------------------
// HTTP Server
// ---------------------------------------------------------------------------

#define TRUSTLESS_SERVER_PORT 8403

static volatile sig_atomic_t server_running = 1;

static void server_signal_handler (int)
{
	server_running = 0;
}

static std::string http_response (int status_code, const std::string& status_text,
				   const std::string& body)
{
	std::stringstream ss;
	ss << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";
	ss << "Content-Type: application/json\r\n";
	ss << "Content-Length: " << body.size() << "\r\n";
	ss << "Connection: close\r\n";
	ss << "\r\n";
	ss << body;
	return ss.str();
}

static void parse_http_request (const std::string& raw, std::string& method,
				 std::string& path, std::string& body)
{
	size_t first_space = raw.find(' ');
	if (first_space == std::string::npos) return;
	method = raw.substr(0, first_space);

	size_t second_space = raw.find(' ', first_space + 1);
	if (second_space == std::string::npos) return;
	path = raw.substr(first_space + 1, second_space - first_space - 1);

	size_t body_start = raw.find("\r\n\r\n");
	if (body_start != std::string::npos) {
		body = raw.substr(body_start + 4);
	}
}

static std::string route_request (const std::string& method, const std::string& path,
				   const std::string& body, const Trustless_config& cfg)
{
	if (path == "/health") {
		return http_response(200, "OK", "{\"status\": \"ok\", \"module\": \"trustless\"}");
	}

	if (path.substr(0, 8) == "/verify/") {
		if (method != "GET") {
			return http_response(405, "Method Not Allowed", "{\"error\": \"use GET\"}");
		}
		std::string id = path.substr(8);
		std::string id_hex = pad_id_hex(id);
		try {
			Chain_verify_result result = trustless_chain_verify(cfg, id_hex);
			std::stringstream json;
			json << "{\"valid\": " << (result.valid ? "true" : "false")
			     << ", \"status\": " << static_cast<int>(result.status)
			     << ", \"expires_at\": " << result.expires_at << "}";
			return http_response(200, "OK", json.str());
		} catch (const Error& e) {
			return http_response(500, "Error", "{\"error\": \"" + e.message + "\"}");
		}
	}

	if (path.substr(0, 6) == "/show/") {
		if (method != "GET") {
			return http_response(405, "Method Not Allowed", "{\"error\": \"use GET\"}");
		}
		std::string id = path.substr(6);
		std::string id_hex = pad_id_hex(id);
		try {
			Chain_license lic = trustless_chain_get_license(cfg, id_hex);
			std::stringstream json;
			json << "{\"id\": \"" << lic.id << "\","
			     << " \"licensee_hash\": \"" << lic.licensee_hash << "\","
			     << " \"licensee_wallet\": \"" << lic.licensee_wallet << "\","
			     << " \"scope_hash\": \"" << lic.scope_hash << "\","
			     << " \"issued_at\": " << lic.issued_at << ","
			     << " \"expires_at\": " << lic.expires_at << ","
			     << " \"status\": " << static_cast<int>(lic.status) << ","
			     << " \"content_hash\": \"" << lic.content_hash << "\"}";
			return http_response(200, "OK", json.str());
		} catch (const Error& e) {
			return http_response(500, "Error", "{\"error\": \"" + e.message + "\"}");
		}
	}

	if (path == "/audit/root") {
		if (method != "GET") {
			return http_response(405, "Method Not Allowed", "{\"error\": \"use GET\"}");
		}
		try {
			Chain_root root = trustless_chain_latest_root(cfg);
			std::stringstream json;
			json << "{\"root\": \"" << root.root << "\","
			     << " \"timestamp\": " << root.timestamp << ","
			     << " \"leaf_count\": " << root.leaf_count << "}";
			return http_response(200, "OK", json.str());
		} catch (const Error& e) {
			return http_response(500, "Error", "{\"error\": \"" + e.message + "\"}");
		}
	}

	if (path == "/config") {
		if (method != "GET") {
			return http_response(405, "Method Not Allowed", "{\"error\": \"use GET\"}");
		}
		std::stringstream json;
		json << "{\"rpc_url\": \"" << cfg.rpc_url << "\","
		     << " \"registry\": \"" << cfg.registry_address << "\","
		     << " \"audit\": \"" << cfg.audit_address << "\"}";
		return http_response(200, "OK", json.str());
	}

	return http_response(404, "Not Found", "{\"error\": \"not found\"}");
}

int trustless_cmd_serve (int argc, const char** argv)
{
	const char* port_str = 0;
	Options_list options;
	options.push_back(Option_def("--port", &port_str));
	parse_options(options, argc, argv);

	int port = port_str ? std::atoi(port_str) : TRUSTLESS_SERVER_PORT;

	Trustless_config cfg = trustless_config_load();

	// Set up signal handling
	struct sigaction sa;
	std::memset(&sa, 0, sizeof(sa));
	sa.sa_handler = server_signal_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) throw Error("Failed to create socket");

	int opt = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

	struct sockaddr_in addr;
	std::memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		close(server_fd);
		throw Error("Failed to bind to port " + std::string(port_str ? port_str : "8403"));
	}

	if (listen(server_fd, 5) < 0) {
		close(server_fd);
		throw Error("Failed to listen");
	}

	std::cerr << "git-crypt-trustless server listening on port " << port << std::endl;
	std::cerr << "Registry: " << cfg.registry_address << std::endl;
	std::cerr << "Endpoints: /health, /verify/{id}, /show/{id}, /audit/root, /config" << std::endl;

	while (server_running) {
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
		if (client_fd < 0) {
			if (!server_running) break;
			continue;
		}

		char buf[4096];
		ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
		if (n > 0) {
			buf[n] = '\0';
			std::string raw(buf);

			std::string method, path, body;
			parse_http_request(raw, method, path, body);

			std::string response = route_request(method, path, body, cfg);
			write(client_fd, response.c_str(), response.size());
		}

		close(client_fd);
	}

	close(server_fd);
	std::cerr << "Server stopped." << std::endl;
	return 0;
}
