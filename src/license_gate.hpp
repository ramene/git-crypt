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

#ifndef GIT_CRYPT_LICENSE_GATE_HPP
#define GIT_CRYPT_LICENSE_GATE_HPP

#include <string>

// Check if the current user has a valid license for the given operation.
// Returns 0 if allowed (no licensing dir = always allowed for backward compat).
// Returns 1 if blocked (license required but not found/expired/revoked).
int		license_check (const std::string& operation);

// Like license_check() but throws Error if blocked.
void		license_require (const std::string& operation);

// Verify a license on-chain via cast receipt.
// Returns true if the tx hash is confirmed on the given RPC.
bool		license_verify_onchain (const std::string& tx_hash,
				        const std::string& rpc_url);

#endif
