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

#ifndef GIT_CRYPT_POLICY_HPP
#define GIT_CRYPT_POLICY_HPP

#include <string>
#include <vector>

struct Policy_owner {
	std::string	fingerprint;	// SSH key fingerprint
	std::string	name;		// Display name
};

struct Policy_member {
	std::string	fingerprint;	// SSH key fingerprint
	std::string	name;		// Display name
	std::string	ssh_pubkey_path;// Path to SSH public key file
};

struct Policy_agent {
	std::string			name;		// Agent name
	std::vector<std::string>	key_scopes;	// Allowed key names
	std::string			age_recipient;	// Age recipient for agent key
};

struct Policy_quorum {
	std::string	operation;	// Operation name (e.g. "add-gpg-user")
	int		required;	// Number of approvals required
};

struct Policy {
	std::vector<Policy_owner>	owners;
	std::vector<Policy_member>	members;
	std::vector<Policy_agent>	agents;
	std::vector<Policy_quorum>	quorums;
};

// Get path to policy file (.git-crypt/policy.txt in repo root)
std::string	policy_path ();

// Check if policy file exists
bool		policy_exists ();

// Load policy from file
Policy		policy_load ();

// Save policy to file
void		policy_save (const Policy& policy);

// Check if a fingerprint is an owner
bool		policy_is_owner (const Policy& policy, const std::string& fingerprint);

// Get quorum requirement for an operation (returns 1 if not specified)
int		policy_quorum_for (const Policy& policy, const std::string& operation);

#endif
