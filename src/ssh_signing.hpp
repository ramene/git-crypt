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

#ifndef GIT_CRYPT_SSH_SIGNING_HPP
#define GIT_CRYPT_SSH_SIGNING_HPP

#include <string>

struct Ssh_signing_error {
	std::string	message;

	explicit Ssh_signing_error (std::string m) : message(m) { }
};

// Sign data using ssh-keygen -Y sign
// Returns the signature as a string (armored SSH signature)
std::string	ssh_sign (const std::string& data, const std::string& key_path);

// Verify a signature using ssh-keygen -Y verify
// Returns true if signature is valid for the given data and principal
bool		ssh_verify (const std::string& data, const std::string& signature,
			    const std::string& allowed_signers_file,
			    const std::string& principal);

// Compute SSH key fingerprint via ssh-keygen -lf
std::string	ssh_key_fingerprint (const std::string& key_path);

// Read user.signingkey from git config
std::string	ssh_get_signing_key_path ();

#endif
