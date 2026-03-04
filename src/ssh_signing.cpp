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

#include "ssh_signing.hpp"
#include "util.hpp"
#include "commands.hpp"
#include <sstream>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

std::string ssh_sign (const std::string& data, const std::string& key_path)
{
	// Write data to a temp file (ssh-keygen reads from file)
	char	tmp_data[] = "/tmp/git-crypt-sign-data-XXXXXX";
	int	fd = mkstemp(tmp_data);
	if (fd < 0) {
		throw Ssh_signing_error("Failed to create temporary file for signing");
	}
	ssize_t	written = write(fd, data.data(), data.size());
	close(fd);
	if (written < 0 || static_cast<size_t>(written) != data.size()) {
		unlink(tmp_data);
		throw Ssh_signing_error("Failed to write data for signing");
	}

	// ssh-keygen -Y sign -f <key> -n git-crypt-proposal <file>
	std::string	sig_file = std::string(tmp_data) + ".sig";
	std::vector<std::string>	command;
	command.push_back("ssh-keygen");
	command.push_back("-Y");
	command.push_back("sign");
	command.push_back("-f");
	command.push_back(key_path);
	command.push_back("-n");
	command.push_back("git-crypt-proposal");
	command.push_back(tmp_data);

	std::stringstream	output;
	if (!successful_exit(exec_command(command, output))) {
		unlink(tmp_data);
		unlink(sig_file.c_str());
		throw Ssh_signing_error("ssh-keygen sign failed");
	}

	// Read the signature file
	std::ifstream	sig_in(sig_file);
	if (!sig_in) {
		unlink(tmp_data);
		unlink(sig_file.c_str());
		throw Ssh_signing_error("Failed to read signature file");
	}
	std::string	signature((std::istreambuf_iterator<char>(sig_in)),
				   std::istreambuf_iterator<char>());
	sig_in.close();

	unlink(tmp_data);
	unlink(sig_file.c_str());

	return signature;
}

bool ssh_verify (const std::string& data, const std::string& signature,
		 const std::string& allowed_signers_file,
		 const std::string& principal)
{
	// Write data to temp file
	char	tmp_data[] = "/tmp/git-crypt-verify-data-XXXXXX";
	int	fd = mkstemp(tmp_data);
	if (fd < 0) {
		return false;
	}
	ssize_t	written = write(fd, data.data(), data.size());
	close(fd);
	if (written < 0 || static_cast<size_t>(written) != data.size()) {
		unlink(tmp_data);
		return false;
	}

	// Write signature to temp file
	char	tmp_sig[] = "/tmp/git-crypt-verify-sig-XXXXXX";
	fd = mkstemp(tmp_sig);
	if (fd < 0) {
		unlink(tmp_data);
		return false;
	}
	written = write(fd, signature.data(), signature.size());
	close(fd);
	if (written < 0 || static_cast<size_t>(written) != signature.size()) {
		unlink(tmp_data);
		unlink(tmp_sig);
		return false;
	}

	// ssh-keygen -Y verify -f <allowed_signers> -I <principal> -n git-crypt-proposal -s <sig> < <data>
	std::vector<std::string>	command;
	command.push_back("ssh-keygen");
	command.push_back("-Y");
	command.push_back("verify");
	command.push_back("-f");
	command.push_back(allowed_signers_file);
	command.push_back("-I");
	command.push_back(principal);
	command.push_back("-n");
	command.push_back("git-crypt-proposal");
	command.push_back("-s");
	command.push_back(tmp_sig);
	command.push_back("<");
	command.push_back(tmp_data);

	// Use exec_command_with_input to feed data via stdin
	bool	result = successful_exit(exec_command_with_input(command, data.data(), data.size()));

	unlink(tmp_data);
	unlink(tmp_sig);

	return result;
}

std::string ssh_key_fingerprint (const std::string& key_path)
{
	// ssh-keygen -lf <key_path>
	std::vector<std::string>	command;
	command.push_back("ssh-keygen");
	command.push_back("-lf");
	command.push_back(key_path);

	std::stringstream	output;
	if (!successful_exit(exec_command(command, output))) {
		throw Ssh_signing_error("Failed to compute SSH key fingerprint");
	}

	// Output format: "2048 SHA256:xxxx comment (RSA)"
	// Extract the SHA256:xxxx part
	std::string	line;
	std::getline(output, line);
	size_t	start = line.find("SHA256:");
	if (start == std::string::npos) {
		// Try the whole line as fallback
		return line;
	}
	size_t	end = line.find(' ', start);
	if (end == std::string::npos) {
		return line.substr(start);
	}
	return line.substr(start, end - start);
}

std::string ssh_get_signing_key_path ()
{
	return get_git_config("user.signingkey");
}
