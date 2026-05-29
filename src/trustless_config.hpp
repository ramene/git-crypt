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

#ifndef GIT_CRYPT_TRUSTLESS_CONFIG_HPP
#define GIT_CRYPT_TRUSTLESS_CONFIG_HPP

#include <string>
#include <vector>

struct Trustless_config {
	std::string		rpc_url;		// Primary RPC URL
	std::vector<std::string> rpc_urls;		// Multi-RPC URLs
	int			rpc_threshold;		// M-of-N agreement threshold
	std::string		chain_id;		// EVM chain ID
	std::string		registry_address;	// LicenseRegistry contract address
	std::string		audit_address;		// MerkleAudit contract address
	std::string		from_address;		// Sender address
	std::string		private_key;		// Private key (from env only)
};

// Load config from env vars + git config.
// Env vars have higher precedence than git config.
// Throws Error if required fields are missing.
Trustless_config	trustless_config_load ();

// Load config without throwing on missing fields.
// Returns partial config (caller checks what they need).
Trustless_config	trustless_config_load_partial ();

// Get a single git config value. Returns empty string if not set.
std::string		trustless_git_config_get (const std::string& key);

// Set a git config value.
void			trustless_git_config_set (const std::string& key,
						  const std::string& value);

// Get the trustless data directory (.git-crypt/trustless/).
std::string		trustless_data_dir ();

// Check if trustless has been initialized (config exists).
bool			trustless_initialized ();

#endif
