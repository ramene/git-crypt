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

#ifndef GIT_CRYPT_PROPOSAL_HPP
#define GIT_CRYPT_PROPOSAL_HPP

#include <string>
#include <vector>
#include <map>

struct Proposal {
	std::string			id;			// Unique proposal ID
	std::string			operation;		// Operation name
	std::string			timestamp;		// ISO 8601
	std::string			proposer_fingerprint;	// SSH fingerprint of proposer
	std::string			status;			// "pending", "approved", "executed", "rejected"
	int				quorum_required;	// Number of approvals needed
	std::map<std::string, std::string>	params;		// Operation parameters
};

// Get path to proposals directory (.git-crypt/proposals/)
std::string	proposals_dir ();

// Create a new proposal, returns proposal ID
std::string	proposal_create (const std::string& operation,
				 const std::string& proposer_fingerprint,
				 int quorum_required,
				 const std::map<std::string, std::string>& params);

// Load a proposal by ID
Proposal	proposal_load (const std::string& id);

// Save a proposal (update status etc.)
void		proposal_save (const Proposal& proposal);

// Record an approval signature for a proposal
void		proposal_approve (const std::string& id,
				  const std::string& fingerprint,
				  const std::string& signature);

// Check if a proposal has met its quorum
bool		proposal_has_quorum (const std::string& id);

// Get list of approval fingerprints for a proposal
std::vector<std::string>	proposal_get_approvals (const std::string& id);

// List all proposals (optionally filter by status)
std::vector<Proposal>	proposal_list (const std::string& status_filter);

#endif
