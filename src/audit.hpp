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

#ifndef GIT_CRYPT_AUDIT_HPP
#define GIT_CRYPT_AUDIT_HPP

#include <string>
#include <vector>
#include <ctime>

struct Audit_entry {
	std::string	timestamp;	// ISO 8601
	std::string	identity;	// GPG fingerprint or age recipient
	std::string	identity_type;	// "gpg", "age", "symmetric", "shamir"
	std::string	operation;	// "unlock", "lock", "export-key", etc.
	std::string	key_name;	// Key name (empty = default)
	std::vector<std::string>	files;		// Files accessed (may be empty)
	std::string	prev_hash;	// SHA-256 hash of previous entry (hex)
	std::string	entry_hash;	// SHA-256 hash of this entry (hex)
	std::string	signature;	// Optional GPG/age signature of entry_hash
};

// Get path to audit log file
std::string	audit_log_path ();

// Compute SHA-256 hash of an audit entry (for hash chain)
std::string	audit_entry_hash (const std::string& timestamp,
				  const std::string& identity,
				  const std::string& identity_type,
				  const std::string& operation,
				  const std::string& key_name,
				  const std::string& prev_hash);

// Append an entry to the audit log
void		audit_log_operation (const std::string& operation,
				    const std::string& identity,
				    const std::string& identity_type,
				    const char* key_name,
				    const std::vector<std::string>& files);

// Read all audit entries from the log file
std::vector<Audit_entry>	audit_read_log ();

// Verify the hash chain integrity of the audit log
// Returns the number of valid entries (0 = empty or all invalid)
size_t		audit_verify_chain (const std::vector<Audit_entry>& entries);

// Get current user identity for audit logging
std::string	audit_get_identity (std::string& identity_type);

// Compute Keccak-256 hash of the current audit log state (for on-chain anchoring)
// Returns hex-encoded hash of all entry hashes concatenated
std::string	audit_state_hash ();

// Publish an audit anchor to an Ethereum-compatible chain
// Returns the transaction hash
std::string	audit_anchor_onchain (const std::string& state_hash,
				      const std::string& rpc_url,
				      const std::string& from_address);

// Get path to the anchors log file
std::string	audit_anchors_path ();

// Record an on-chain anchor in the local anchors log
void		audit_record_anchor (const std::string& state_hash,
				     const std::string& tx_hash,
				     const std::string& rpc_url,
				     size_t entry_count);

// Read anchor records
struct Audit_anchor {
	std::string	timestamp;
	std::string	state_hash;
	std::string	tx_hash;
	std::string	rpc_url;
	size_t		entry_count;
};
std::vector<Audit_anchor>	audit_read_anchors ();

#endif
