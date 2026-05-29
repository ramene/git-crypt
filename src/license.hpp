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

#ifndef GIT_CRYPT_LICENSE_HPP
#define GIT_CRYPT_LICENSE_HPP

#include <string>
#include <vector>

struct License {
	std::string	id;			// 16 hex chars (8 random bytes)
	std::string	licensee_fingerprint;	// SSH key fingerprint
	std::string	licensee_wallet;	// Ethereum wallet address (optional)
	std::string	scope;			// Comma-separated operations (or "*")
	std::string	issued_at;		// ISO 8601 timestamp
	std::string	expires_at;		// ISO 8601 timestamp
	std::string	status;			// "active", "revoked", "expired"
	std::string	anchor_tx;		// On-chain tx hash (optional)
	std::string	anchor_rpc;		// RPC URL used for anchoring (optional)
};

// Generate a unique license ID (16 hex chars from 8 random bytes)
std::string	license_generate_id ();

// License directory path: .git-crypt/licenses/<id>/
std::string	license_dir (const std::string& id);

// License file path: .git-crypt/licenses/<id>/license.txt
std::string	license_path (const std::string& id);

// Signatures directory: .git-crypt/licenses/<id>/signatures/
std::string	license_sig_dir (const std::string& id);

// Signature file: .git-crypt/licenses/<id>/signatures/<fingerprint>.sig
std::string	license_sig_path (const std::string& id, const std::string& fingerprint);

// Create a new license, write to disk, return the license
License		license_create (const std::string& licensee_fingerprint,
			        const std::string& licensee_wallet,
			        const std::string& scope,
			        const std::string& expires_at);

// Load license from disk by ID
License		license_load (const std::string& id);

// Save license to disk (overwrites)
void		license_save (const License& license);

// Sign a license with the issuer's SSH key
void		license_sign (const std::string& id, const std::string& key_path);

// Verify all signatures on a license
bool		license_verify_signatures (const std::string& id);

// List all license IDs in .git-crypt/licenses/
std::vector<std::string>	license_list_ids ();

// Check if license has a specific operation in scope
bool		license_scope_contains (const License& license, const std::string& operation);

// Check if a license is currently valid (not expired, not revoked)
bool		license_is_valid (const License& license);

// Compute SHA-256 hash of license contents (for anchoring)
std::string	license_hash (const License& license);

// Serialize license to portable string (for export/import)
std::string	license_serialize (const License& license);

// Deserialize license from portable string
License		license_deserialize (const std::string& data);

// Check if licensing is initialized (.git-crypt/licenses/ exists with issuer)
bool		license_initialized ();

// Get issuer fingerprint from .git-crypt/licenses/issuer.txt
std::string	license_issuer_fingerprint ();

#endif
