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

#ifndef GIT_CRYPT_TRUSTLESS_MERKLE_HPP
#define GIT_CRYPT_TRUSTLESS_MERKLE_HPP

#include <string>
#include <vector>
#include <cstdint>

struct MerkleProof {
	std::vector<std::string>	siblings;	// Sibling hashes (hex)
	std::vector<uint8_t>		directions;	// 0=left, 1=right
	uint32_t			leaf_index;
};

class MerkleTree {
	std::vector<std::string>	leaves;		// Leaf hashes (hex, keccak256)
	std::vector<std::string>	tree;		// Full tree array (index 0 unused, index 1 = root)

public:
	// Append a new leaf hash and rebuild the tree.
	void		append (const std::string& leaf_hash);

	// Rebuild the internal tree from current leaves.
	void		rebuild ();

	// Get the current root hash. Returns empty string if no leaves.
	std::string	root () const;

	// Generate a proof for the leaf at the given index.
	MerkleProof	proof (uint32_t leaf_index) const;

	// Static verification: check a leaf+proof matches a root.
	static bool	verify (const std::string& leaf,
				const MerkleProof& proof,
				const std::string& expected_root);

	// Persistence: save tree to binary file.
	// Format: [4-byte leaf_count][32-byte hash per leaf]
	void		save (const std::string& path) const;

	// Persistence: load tree from binary file.
	void		load (const std::string& path);

	// Get the number of leaves.
	uint32_t	leaf_count () const { return static_cast<uint32_t>(leaves.size()); }

	// Get a specific leaf hash.
	std::string	leaf_at (uint32_t index) const;

	// Compute keccak256 of two concatenated 32-byte hashes.
	static std::string hash_pair (const std::string& left, const std::string& right);

	// Compute keccak256 of arbitrary data (hex-encoded output).
	static std::string keccak256 (const std::string& data);
};

// Serialize a MerkleProof to JSON string.
std::string	merkle_proof_to_json (const MerkleProof& proof);

// Deserialize a MerkleProof from JSON string.
MerkleProof	merkle_proof_from_json (const std::string& json);

#endif
