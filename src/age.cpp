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

#include "age.hpp"
#include "util.hpp"
#include "commands.hpp"
#include <sstream>
#include <cstdlib>
#include <openssl/sha.h>

static std::string age_get_executable ()
{
	std::string	agebin = "age";
	try {
		agebin = get_git_config("age.program");
	} catch (...) {
	}
	return agebin;
}

bool age_is_available ()
{
	std::vector<std::string>	command;
	command.push_back(age_get_executable());
	command.push_back("--version");
	std::stringstream		output;
	return successful_exit(exec_command(command, output));
}

std::string age_recipient_hash (const std::string& recipient)
{
	unsigned char	hash[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(recipient.data()), recipient.size(), hash);

	// Convert first 20 bytes to 40 hex chars (matching GPG fingerprint length)
	static const char	hex_chars[] = "0123456789abcdef";
	std::string		result;
	result.reserve(40);
	for (int i = 0; i < 20; ++i) {
		result += hex_chars[(hash[i] >> 4) & 0x0f];
		result += hex_chars[hash[i] & 0x0f];
	}
	return result;
}

void age_encrypt_to_file (const std::string& filename, const std::string& recipient, const char* p, size_t len)
{
	// age -r RECIPIENT -o FILENAME  (reads plaintext from stdin)
	std::vector<std::string>	command;
	command.push_back(age_get_executable());
	command.push_back("-r");
	command.push_back(recipient);
	command.push_back("-o");
	command.push_back(filename);
	if (!successful_exit(exec_command_with_input(command, p, len))) {
		throw Age_error("Failed to encrypt with age");
	}
}

bool age_decrypt_from_file (const std::string& filename, std::ostream& output)
{
	// age -d [-i IDENTITY] FILENAME  (writes plaintext to stdout)
	std::vector<std::string>	command;
	command.push_back(age_get_executable());
	command.push_back("-d");

	// Check for identity file: git config age.identity > $AGE_IDENTITY env var
	std::string	identity;
	try {
		identity = get_git_config("age.identity");
	} catch (...) {
		const char*	env_identity = std::getenv("AGE_IDENTITY");
		if (env_identity) {
			identity = env_identity;
		}
	}
	if (!identity.empty()) {
		command.push_back("-i");
		command.push_back(identity);
	}

	command.push_back(filename);
	return successful_exit(exec_command(command, output));
}

bool age_yubikey_is_available ()
{
	std::vector<std::string>	command;
	command.push_back("age-plugin-yubikey");
	command.push_back("--list");
	std::stringstream		output;
	return successful_exit(exec_command(command, output));
}

std::vector<std::string> age_yubikey_list_recipients ()
{
	// age-plugin-yubikey --list outputs recipient lines like:
	// #       Serial: 12345678, Slot: 1
	// age1yubikey1...
	std::vector<std::string>	command;
	command.push_back("age-plugin-yubikey");
	command.push_back("--list");
	std::stringstream		command_output;
	if (!successful_exit(exec_command(command, command_output))) {
		throw Age_error("age-plugin-yubikey --list failed");
	}

	std::vector<std::string>	recipients;
	std::string			line;
	while (std::getline(command_output, line)) {
		// Skip comment lines (start with #) and empty lines
		if (line.empty() || line[0] == '#') {
			continue;
		}
		// Recipient lines start with "age1yubikey1"
		if (line.compare(0, 12, "age1yubikey1") == 0) {
			recipients.push_back(line);
		}
	}
	return recipients;
}
