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

#ifndef GIT_CRYPT_TRUSTLESS_CHAIN_HPP
#define GIT_CRYPT_TRUSTLESS_CHAIN_HPP

#include <string>
#include <vector>

struct Trustless_config;

// Execute a cast call (read-only, free) against a contract.
// Returns the raw output from cast.
std::string	trustless_cast_call (const Trustless_config& cfg,
				     const std::string& contract_address,
				     const std::string& function_sig,
				     const std::vector<std::string>& args = std::vector<std::string>());

// Execute a cast send (write tx, costs gas) against a contract.
// Returns the transaction hash.
std::string	trustless_cast_send (const Trustless_config& cfg,
				     const std::string& contract_address,
				     const std::string& function_sig,
				     const std::vector<std::string>& args = std::vector<std::string>());

// Deploy a contract via forge script.
// Returns a pair of (registry_address, audit_address).
struct Deploy_result {
	std::string	registry_address;
	std::string	audit_address;
};
Deploy_result	trustless_deploy_contracts (const Trustless_config& cfg,
					    const std::string& contracts_dir);

// Issue a license on-chain.
// Returns the transaction hash.
std::string	trustless_chain_issue (const Trustless_config& cfg,
				       const std::string& id_hex,
				       const std::string& licensee_hash,
				       const std::string& licensee_wallet,
				       const std::string& scope_hash,
				       uint64_t issued_at,
				       uint64_t expires_at,
				       const std::string& content_hash);

// Revoke a license on-chain.
// Returns the transaction hash.
std::string	trustless_chain_revoke (const Trustless_config& cfg,
					const std::string& id_hex);

// Verify a license on-chain.
// Returns (valid, status, expiresAt).
struct Chain_verify_result {
	bool		valid;
	uint8_t		status;		// 0=active, 1=revoked
	uint64_t	expires_at;
};
Chain_verify_result trustless_chain_verify (const Trustless_config& cfg,
					    const std::string& id_hex);

// Get a license from chain.
struct Chain_license {
	std::string	id;
	std::string	licensee_hash;
	std::string	licensee_wallet;
	std::string	scope_hash;
	uint64_t	issued_at;
	uint64_t	expires_at;
	uint8_t		status;
	std::string	content_hash;
};
Chain_license	trustless_chain_get_license (const Trustless_config& cfg,
					     const std::string& id_hex);

// Get total license count from chain.
uint64_t	trustless_chain_license_count (const Trustless_config& cfg);

// Commit a Merkle root on-chain.
std::string	trustless_chain_commit_root (const Trustless_config& cfg,
					     const std::string& root_hash,
					     uint64_t leaf_count);

// Get latest Merkle root from chain.
struct Chain_root {
	std::string	root;
	uint64_t	timestamp;
	uint64_t	leaf_count;
};
Chain_root	trustless_chain_latest_root (const Trustless_config& cfg);

// Verify a Merkle entry on-chain.
bool		trustless_chain_verify_entry (const Trustless_config& cfg,
					      const std::string& leaf,
					      const std::vector<std::string>& proof,
					      uint64_t index,
					      uint64_t root_index);

// Compute keccak256 hash (via cast).
std::string	trustless_keccak256 (const std::string& input);

#endif
