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

#include "license_gate.hpp"
#include "license.hpp"
#include "ssh_signing.hpp"
#include "util.hpp"
#include "commands.hpp"
#include <vector>
#include <string>
#include <sstream>
#include <iostream>

int license_check (const std::string& operation)
{
	if (!license_initialized()) {
		return 0;
	}

	std::string	key_path;
	std::string	fingerprint;
	try {
		key_path = ssh_get_signing_key_path();
		fingerprint = ssh_key_fingerprint(key_path);
	} catch (...) {
		std::cerr << "git-crypt: cannot determine SSH key fingerprint for license check" << std::endl;
		return 1;
	}

	std::vector<std::string>	ids = license_list_ids();
	for (size_t i = 0; i < ids.size(); ++i) {
		try {
			License	lic = license_load(ids[i]);
			if (lic.licensee_fingerprint == fingerprint &&
			    license_is_valid(lic) &&
			    license_scope_contains(lic, operation)) {
				return 0;
			}
		} catch (...) {
			continue;
		}
	}

	std::cerr << "git-crypt: no valid license found for operation: " << operation << std::endl;
	return 1;
}

void license_require (const std::string& operation)
{
	if (license_check(operation) != 0) {
		throw Error("Valid license required for operation: " + operation);
	}
}

bool license_verify_onchain (const std::string& tx_hash, const std::string& rpc_url)
{
	std::vector<std::string>	command;
	command.push_back("cast");
	command.push_back("receipt");
	command.push_back("--rpc-url");
	command.push_back(rpc_url);
	command.push_back(tx_hash);

	std::stringstream	output;
	int	wait_status = exec_command(command, output);
	if (!successful_exit(wait_status)) {
		return false;
	}

	std::string	result = output.str();
	// Check for successful transaction status
	// cast receipt outputs "status" field with 1 (success) or 0 (failure)
	std::string	line;
	std::istringstream	lines(result);
	while (std::getline(lines, line)) {
		if (line.find("status") != std::string::npos) {
			if (line.find("0x1") != std::string::npos || line.find(" 1") != std::string::npos) {
				return true;
			}
		}
	}
	return false;
}
