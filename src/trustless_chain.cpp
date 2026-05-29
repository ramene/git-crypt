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

#include "trustless_chain.hpp"
#include "trustless_config.hpp"
#include "commands.hpp"
#include "util.hpp"
#include <sstream>
#include <cstdlib>
#include <cstdint>
#include <iostream>

static std::string trim (const std::string& s)
{
	size_t start = s.find_first_not_of(" \t\n\r");
	size_t end = s.find_last_not_of(" \t\n\r");
	if (start == std::string::npos) return "";
	return s.substr(start, end - start + 1);
}

static std::string to_hex_uint64 (uint64_t val)
{
	std::stringstream ss;
	ss << val;
	return ss.str();
}

std::string trustless_cast_call (const Trustless_config& cfg,
				  const std::string& contract_address,
				  const std::string& function_sig,
				  const std::vector<std::string>& args)
{
	std::vector<std::string> command;
	command.push_back("cast");
	command.push_back("call");
	command.push_back("--rpc-url");
	command.push_back(cfg.rpc_url);
	command.push_back(contract_address);
	command.push_back(function_sig);
	for (size_t i = 0; i < args.size(); ++i) {
		command.push_back(args[i]);
	}

	std::stringstream output;
	int status = exec_command(command, output);
	if (!successful_exit(status)) {
		throw Error("cast call failed for " + function_sig);
	}

	return trim(output.str());
}

std::string trustless_cast_send (const Trustless_config& cfg,
				  const std::string& contract_address,
				  const std::string& function_sig,
				  const std::vector<std::string>& args)
{
	std::vector<std::string> command;
	command.push_back("cast");
	command.push_back("send");
	command.push_back("--rpc-url");
	command.push_back(cfg.rpc_url);

	if (!cfg.private_key.empty()) {
		command.push_back("--private-key");
		command.push_back(cfg.private_key);
	} else if (!cfg.from_address.empty()) {
		command.push_back("--from");
		command.push_back(cfg.from_address);
	}

	command.push_back(contract_address);
	command.push_back(function_sig);
	for (size_t i = 0; i < args.size(); ++i) {
		command.push_back(args[i]);
	}

	std::stringstream output;
	int status = exec_command(command, output);
	if (!successful_exit(status)) {
		throw Error("cast send failed for " + function_sig);
	}

	// Parse transaction hash from output
	std::string result = output.str();
	// cast send outputs multiple lines; the tx hash is typically on the
	// "transactionHash" line or the first 0x... line
	std::istringstream lines(result);
	std::string line;
	while (std::getline(lines, line)) {
		std::string trimmed = trim(line);
		if (trimmed.size() == 66 && trimmed.substr(0, 2) == "0x") {
			return trimmed;
		}
		// Look for "transactionHash" field
		size_t pos = trimmed.find("transactionHash");
		if (pos != std::string::npos) {
			size_t hash_start = trimmed.find("0x", pos);
			if (hash_start != std::string::npos) {
				return trimmed.substr(hash_start, 66);
			}
		}
	}

	// Fallback: return trimmed full output
	return trim(result);
}

Deploy_result trustless_deploy_contracts (const Trustless_config& cfg,
					   const std::string& contracts_dir)
{
	std::vector<std::string> command;
	command.push_back("forge");
	command.push_back("script");
	command.push_back(contracts_dir + "/script/Deploy.s.sol");
	command.push_back("--rpc-url");
	command.push_back(cfg.rpc_url);

	if (!cfg.private_key.empty()) {
		command.push_back("--private-key");
		command.push_back(cfg.private_key);
	}

	command.push_back("--broadcast");

	std::stringstream output;
	int status = exec_command(command, output);
	if (!successful_exit(status)) {
		throw Error("Contract deployment failed. Check forge output.");
	}

	// Parse deployed addresses from forge output
	Deploy_result result;
	std::string out_str = output.str();
	std::istringstream lines(out_str);
	std::string line;
	while (std::getline(lines, line)) {
		if (line.find("LicenseRegistry deployed") != std::string::npos ||
		    line.find("Registry:") != std::string::npos) {
			size_t pos = line.find("0x");
			if (pos != std::string::npos) {
				result.registry_address = line.substr(pos, 42);
			}
		}
		if (line.find("MerkleAudit deployed") != std::string::npos ||
		    line.find("Audit:") != std::string::npos) {
			size_t pos = line.find("0x");
			if (pos != std::string::npos) {
				result.audit_address = line.substr(pos, 42);
			}
		}
	}

	// If we couldn't parse from named output, try the broadcast JSON
	if (result.registry_address.empty() || result.audit_address.empty()) {
		// Forge writes deployment data to broadcast/ directory
		// For now, re-read from forge output lines with "Contract Address:"
		std::istringstream lines2(out_str);
		std::vector<std::string> addresses;
		while (std::getline(lines2, line)) {
			size_t pos = line.find("Contract Address:");
			if (pos == std::string::npos) {
				pos = line.find("contract address:");
			}
			if (pos != std::string::npos) {
				size_t addr_start = line.find("0x", pos);
				if (addr_start != std::string::npos) {
					addresses.push_back(line.substr(addr_start, 42));
				}
			}
		}
		if (addresses.size() >= 2) {
			if (result.registry_address.empty()) result.registry_address = addresses[0];
			if (result.audit_address.empty()) result.audit_address = addresses[1];
		}
	}

	return result;
}

std::string trustless_chain_issue (const Trustless_config& cfg,
				    const std::string& id_hex,
				    const std::string& licensee_hash,
				    const std::string& licensee_wallet,
				    const std::string& scope_hash,
				    uint64_t issued_at,
				    uint64_t expires_at,
				    const std::string& content_hash)
{
	std::vector<std::string> args;
	args.push_back(id_hex);
	args.push_back(licensee_hash);
	args.push_back(licensee_wallet.empty() ? "0x0000000000000000000000000000000000000000" : licensee_wallet);
	args.push_back(scope_hash);
	args.push_back(to_hex_uint64(issued_at));
	args.push_back(to_hex_uint64(expires_at));
	args.push_back(content_hash);

	return trustless_cast_send(cfg, cfg.registry_address,
		"issue(bytes16,bytes32,address,bytes32,uint64,uint64,bytes32)", args);
}

std::string trustless_chain_revoke (const Trustless_config& cfg,
				     const std::string& id_hex)
{
	std::vector<std::string> args;
	args.push_back(id_hex);

	return trustless_cast_send(cfg, cfg.registry_address,
		"revoke(bytes16)", args);
}

Chain_verify_result trustless_chain_verify (const Trustless_config& cfg,
					     const std::string& id_hex)
{
	std::vector<std::string> args;
	args.push_back(id_hex);

	std::string result = trustless_cast_call(cfg, cfg.registry_address,
		"verify(bytes16)(bool,uint8,uint64)", args);

	Chain_verify_result out;
	out.valid = false;
	out.status = 0;
	out.expires_at = 0;

	// Parse cast call output: typically "true\n0\n1234567890" or similar
	std::istringstream lines(result);
	std::string line;
	int field = 0;
	while (std::getline(lines, line)) {
		std::string t = trim(line);
		if (t.empty()) continue;
		switch (field) {
		case 0:
			out.valid = (t == "true" || t == "1");
			break;
		case 1:
			out.status = static_cast<uint8_t>(std::atoi(t.c_str()));
			break;
		case 2:
			out.expires_at = static_cast<uint64_t>(std::strtoull(t.c_str(), NULL, 10));
			break;
		}
		++field;
	}

	return out;
}

Chain_license trustless_chain_get_license (const Trustless_config& cfg,
					    const std::string& id_hex)
{
	std::vector<std::string> args;
	args.push_back(id_hex);

	std::string result = trustless_cast_call(cfg, cfg.registry_address,
		"getLicense(bytes16)(bytes16,bytes32,address,bytes32,uint64,uint64,uint8,bytes32)", args);

	Chain_license lic;
	std::istringstream lines(result);
	std::string line;
	int field = 0;
	while (std::getline(lines, line)) {
		std::string t = trim(line);
		if (t.empty()) continue;
		switch (field) {
		case 0: lic.id = t; break;
		case 1: lic.licensee_hash = t; break;
		case 2: lic.licensee_wallet = t; break;
		case 3: lic.scope_hash = t; break;
		case 4: lic.issued_at = static_cast<uint64_t>(std::strtoull(t.c_str(), NULL, 10)); break;
		case 5: lic.expires_at = static_cast<uint64_t>(std::strtoull(t.c_str(), NULL, 10)); break;
		case 6: lic.status = static_cast<uint8_t>(std::atoi(t.c_str())); break;
		case 7: lic.content_hash = t; break;
		}
		++field;
	}

	return lic;
}

uint64_t trustless_chain_license_count (const Trustless_config& cfg)
{
	std::string result = trustless_cast_call(cfg, cfg.registry_address,
		"getLicenseCount()(uint256)");
	return static_cast<uint64_t>(std::strtoull(trim(result).c_str(), NULL, 10));
}

std::string trustless_chain_commit_root (const Trustless_config& cfg,
					  const std::string& root_hash,
					  uint64_t leaf_count)
{
	if (cfg.audit_address.empty()) {
		throw Error("No audit contract address configured.");
	}

	std::vector<std::string> args;
	args.push_back(root_hash);
	args.push_back(to_hex_uint64(leaf_count));

	return trustless_cast_send(cfg, cfg.audit_address,
		"commitRoot(bytes32,uint256)", args);
}

Chain_root trustless_chain_latest_root (const Trustless_config& cfg)
{
	if (cfg.audit_address.empty()) {
		throw Error("No audit contract address configured.");
	}

	std::string result = trustless_cast_call(cfg, cfg.audit_address,
		"latestRoot()(bytes32,uint256,uint256)");

	Chain_root out;
	out.timestamp = 0;
	out.leaf_count = 0;

	std::istringstream lines(result);
	std::string line;
	int field = 0;
	while (std::getline(lines, line)) {
		std::string t = trim(line);
		if (t.empty()) continue;
		switch (field) {
		case 0: out.root = t; break;
		case 1: out.timestamp = static_cast<uint64_t>(std::strtoull(t.c_str(), NULL, 10)); break;
		case 2: out.leaf_count = static_cast<uint64_t>(std::strtoull(t.c_str(), NULL, 10)); break;
		}
		++field;
	}

	return out;
}

bool trustless_chain_verify_entry (const Trustless_config& cfg,
				    const std::string& leaf,
				    const std::vector<std::string>& proof,
				    uint64_t index,
				    uint64_t root_index)
{
	if (cfg.audit_address.empty()) {
		throw Error("No audit contract address configured.");
	}

	// Build the proof array as a Solidity-compatible string
	std::string proof_array = "[";
	for (size_t i = 0; i < proof.size(); ++i) {
		if (i > 0) proof_array += ",";
		proof_array += proof[i];
	}
	proof_array += "]";

	std::vector<std::string> args;
	args.push_back(leaf);
	args.push_back(proof_array);
	args.push_back(to_hex_uint64(index));
	args.push_back(to_hex_uint64(root_index));

	std::string result = trustless_cast_call(cfg, cfg.audit_address,
		"verifyEntry(bytes32,bytes32[],uint256,uint256)(bool)", args);

	std::string t = trim(result);
	return (t == "true" || t == "1");
}

std::string trustless_keccak256 (const std::string& input)
{
	std::vector<std::string> command;
	command.push_back("cast");
	command.push_back("keccak");
	command.push_back(input);

	std::stringstream output;
	int status = exec_command(command, output);
	if (!successful_exit(status)) {
		throw Error("cast keccak failed");
	}

	return trim(output.str());
}
