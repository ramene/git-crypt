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

#include "trustless_migrate.hpp"
#include "trustless_config.hpp"
#include "trustless_chain.hpp"
#include "license.hpp"
#include "commands.hpp"
#include "util.hpp"
#include <iostream>
#include <sstream>
#include <ctime>

static uint64_t iso8601_to_unix (const std::string& ts)
{
	struct tm tm;
	std::memset(&tm, 0, sizeof(tm));

	// Parse "YYYY-MM-DDTHH:MM:SSZ" format
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

bool trustless_has_license_data ()
{
	return license_initialized();
}

std::vector<std::string> trustless_migration_candidates ()
{
	if (!trustless_has_license_data()) {
		return std::vector<std::string>();
	}
	return license_list_ids();
}

Migration_result trustless_migrate_one (const Trustless_config& cfg,
					 const std::string& license_id)
{
	Migration_result result;
	result.license_id = license_id;
	result.success = false;

	try {
		License lic = license_load(license_id);

		// Compute hashes for on-chain storage
		std::string licensee_hash = trustless_keccak256(lic.licensee_fingerprint);
		std::string scope_hash = trustless_keccak256(lic.scope);
		std::string content_hash = "0x" + license_hash(lic);

		// Convert timestamps
		uint64_t issued_at = iso8601_to_unix(lic.issued_at);
		uint64_t expires_at = iso8601_to_unix(lic.expires_at);

		// Pack the 16-char hex ID into bytes16
		std::string id_hex = "0x" + lic.id;
		// Pad to 32 hex chars (16 bytes) if needed
		while (id_hex.size() < 34) {  // "0x" + 32 hex chars
			id_hex += "00";
		}

		// Issue on-chain
		result.tx_hash = trustless_chain_issue(
			cfg,
			id_hex,
			licensee_hash,
			lic.licensee_wallet,
			scope_hash,
			issued_at,
			expires_at,
			content_hash
		);

		result.success = true;

		// If original license was revoked, revoke on-chain too
		if (lic.status == "revoked") {
			trustless_chain_revoke(cfg, id_hex);
		}

	} catch (const Error& e) {
		result.error = e.message;
	} catch (const std::exception& e) {
		result.error = e.what();
	}

	return result;
}

std::vector<Migration_result> trustless_migrate_all (const Trustless_config& cfg)
{
	std::vector<std::string> ids = trustless_migration_candidates();
	std::vector<Migration_result> results;

	for (size_t i = 0; i < ids.size(); ++i) {
		std::cerr << "Migrating license " << ids[i] << " (" << (i + 1) << "/" << ids.size() << ")..." << std::endl;
		results.push_back(trustless_migrate_one(cfg, ids[i]));
	}

	return results;
}
