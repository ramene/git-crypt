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

#ifndef GIT_CRYPT_TRUSTLESS_MIGRATE_HPP
#define GIT_CRYPT_TRUSTLESS_MIGRATE_HPP

#include <string>
#include <vector>

struct Trustless_config;

struct Migration_result {
	std::string	license_id;
	std::string	tx_hash;
	bool		success;
	std::string	error;
};

// Migrate a single git-crypt-license to on-chain.
// Loads the license from .git-crypt/licenses/<id>/, computes hashes,
// and calls issue() on the LicenseRegistry contract.
Migration_result trustless_migrate_one (const Trustless_config& cfg,
					 const std::string& license_id);

// Migrate all git-crypt-license licenses to on-chain.
std::vector<Migration_result> trustless_migrate_all (const Trustless_config& cfg);

// Check if git-crypt-license data exists for migration.
bool		trustless_has_license_data ();

// List license IDs available for migration.
std::vector<std::string> trustless_migration_candidates ();

#endif
