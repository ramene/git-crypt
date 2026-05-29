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

#include "trustless_zk.hpp"
#include "trustless_config.hpp"
#include "trustless_merkle.hpp"
#include "commands.hpp"
#include "util.hpp"
#include <iostream>
#include <sstream>
#include <vector>

// Phase 2: ZK proof generation and verification.
// These are stubs in v0.1.0 — full implementation will use snarkjs subprocess.

std::string trustless_zk_generate_proof (const Trustless_config& cfg,
					  const std::string& license_id,
					  const std::string& operation,
					  const MerkleProof& inclusion_proof,
					  const std::string& contract_root)
{
	std::cerr << "ZK proofs are not available in v0.1.0 (Phase 2 feature)." << std::endl;
	std::cerr << "See doc/trustless-guide.md section 6 for the planned implementation." << std::endl;
	return "";
}

bool trustless_zk_verify_proof_local (const std::string& proof_path,
				       const std::string& verification_key_path)
{
	std::cerr << "ZK proof verification is not available in v0.1.0 (Phase 2 feature)." << std::endl;
	return false;
}

bool trustless_zk_verify_proof_onchain (const Trustless_config& cfg,
					 const std::string& proof_path)
{
	std::cerr << "On-chain ZK verification is not available in v0.1.0 (Phase 2 feature)." << std::endl;
	return false;
}

bool trustless_zk_available ()
{
	// Check if snarkjs is installed
	std::vector<std::string> command;
	command.push_back("snarkjs");
	command.push_back("--version");

	std::stringstream output;
	int status = exec_command(command, output);
	return successful_exit(status);
}
