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

#ifndef GIT_CRYPT_TRUSTLESS_RPC_HPP
#define GIT_CRYPT_TRUSTLESS_RPC_HPP

#include <string>
#include <vector>
#include <map>

struct Trustless_config;

// Query multiple RPCs and require M-of-N agreement.
// The function_sig and args define the cast call to make.
// Returns the agreed-upon result, or throws Error if consensus fails.
std::string	trustless_rpc_consensus_call (const Trustless_config& cfg,
					      const std::string& contract_address,
					      const std::string& function_sig,
					      const std::vector<std::string>& args = std::vector<std::string>());

// Query multiple RPCs for a verify result.
// Returns the result that M-of-N RPCs agree on.
struct Rpc_verify_result {
	bool		valid;
	uint8_t		status;
	uint64_t	expires_at;
	bool		consensus_reached;
	int		agreeing_count;
	int		total_count;
};
Rpc_verify_result trustless_rpc_consensus_verify (const Trustless_config& cfg,
						   const std::string& id_hex);

// Check if multi-RPC mode is configured.
bool		trustless_rpc_is_multi (const Trustless_config& cfg);

#endif
