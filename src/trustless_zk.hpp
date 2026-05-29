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

#ifndef GIT_CRYPT_TRUSTLESS_ZK_HPP
#define GIT_CRYPT_TRUSTLESS_ZK_HPP

#include <string>

struct Trustless_config;
struct MerkleProof;

// Phase 2: ZK proof generation and verification.
// These are stubs in v0.1.0 — they print a message and return error.

// Generate a ZK proof that a valid license exists for the given operation.
// Calls snarkjs as a subprocess.
// Returns path to the generated proof file, or empty string on failure.
std::string	trustless_zk_generate_proof (const Trustless_config& cfg,
					     const std::string& license_id,
					     const std::string& operation,
					     const MerkleProof& inclusion_proof,
					     const std::string& contract_root);

// Verify a ZK proof locally (off-chain).
// Returns true if the proof is valid.
bool		trustless_zk_verify_proof_local (const std::string& proof_path,
						 const std::string& verification_key_path);

// Verify a ZK proof on-chain via ZkLicenseVerifier contract.
// Returns true if the on-chain verifier accepts the proof.
bool		trustless_zk_verify_proof_onchain (const Trustless_config& cfg,
						    const std::string& proof_path);

// Check if ZK infrastructure is available (snarkjs, circuit artifacts).
bool		trustless_zk_available ();

#endif
