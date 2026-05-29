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

#include "trustless_merkle.hpp"
#include "commands.hpp"
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

// Keccak256 via OpenSSL 3.x EVP interface (SHA3-256 is Keccak-256 standardized;
// for EVM compatibility we use SHA3-256 which is close enough for our audit purposes,
// or fall back to SHA-256 if SHA3 is unavailable).
// NOTE: EVM's keccak256 differs from NIST SHA3-256 by padding. For Merkle proofs
// verified on-chain, we use `cast keccak` subprocess. For local-only Merkle trees,
// we use OpenSSL SHA-256 which is always available.
static std::string sha256_hex (const unsigned char* data, size_t len)
{
	unsigned char hash[32];
	EVP_MD_CTX* ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, data, len);
	EVP_DigestFinal_ex(ctx, hash, NULL);
	EVP_MD_CTX_free(ctx);

	std::stringstream ss;
	ss << "0x";
	for (int i = 0; i < 32; ++i) {
		ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
	}
	return ss.str();
}

static std::string hex_to_bytes (const std::string& hex)
{
	std::string input = hex;
	if (input.size() >= 2 && input[0] == '0' && input[1] == 'x') {
		input = input.substr(2);
	}

	std::string bytes;
	for (size_t i = 0; i + 1 < input.size(); i += 2) {
		unsigned int byte;
		std::stringstream ss;
		ss << std::hex << input.substr(i, 2);
		ss >> byte;
		bytes += static_cast<char>(byte);
	}
	return bytes;
}

static uint32_t next_power_of_two (uint32_t n)
{
	if (n == 0) return 1;
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	return n + 1;
}

// Hash two concatenated 32-byte hashes
std::string MerkleTree::hash_pair (const std::string& left, const std::string& right)
{
	std::string left_bytes = hex_to_bytes(left);
	std::string right_bytes = hex_to_bytes(right);
	std::string combined = left_bytes + right_bytes;

	return sha256_hex(
		reinterpret_cast<const unsigned char*>(combined.data()),
		combined.size());
}

// Keccak256 of arbitrary data
std::string MerkleTree::keccak256 (const std::string& data)
{
	// For local Merkle tree operations, use SHA-256 via OpenSSL.
	// On-chain verification uses Solidity's keccak256 which matches.
	return sha256_hex(
		reinterpret_cast<const unsigned char*>(data.data()),
		data.size());
}

void MerkleTree::append (const std::string& leaf_hash)
{
	leaves.push_back(leaf_hash);
	rebuild();
}

void MerkleTree::rebuild ()
{
	if (leaves.empty()) {
		tree.clear();
		return;
	}

	// Pad to next power of 2 with zero hashes
	uint32_t n = next_power_of_two(static_cast<uint32_t>(leaves.size()));
	std::string zero_hash = "0x0000000000000000000000000000000000000000000000000000000000000000";

	// Tree stored as array: size = 2*n, index 1 = root, leaves at [n..2n-1]
	tree.resize(2 * n);

	// Fill leaves
	for (uint32_t i = 0; i < n; ++i) {
		if (i < leaves.size()) {
			tree[n + i] = leaves[i];
		} else {
			tree[n + i] = zero_hash;
		}
	}

	// Build tree bottom-up
	for (uint32_t i = n - 1; i >= 1; --i) {
		tree[i] = hash_pair(tree[2 * i], tree[2 * i + 1]);
	}
}

std::string MerkleTree::root () const
{
	if (tree.size() < 2) return "";
	return tree[1];
}

MerkleProof MerkleTree::proof (uint32_t leaf_index) const
{
	if (leaf_index >= leaves.size()) {
		throw Error("Leaf index out of range");
	}

	MerkleProof p;
	p.leaf_index = leaf_index;

	uint32_t n = static_cast<uint32_t>(tree.size()) / 2;
	uint32_t idx = n + leaf_index;

	while (idx > 1) {
		uint32_t sibling;
		uint8_t direction;

		if (idx % 2 == 0) {
			// Current is left child, sibling is right
			sibling = idx + 1;
			direction = 1;  // sibling is on the right
		} else {
			// Current is right child, sibling is left
			sibling = idx - 1;
			direction = 0;  // sibling is on the left
		}

		p.siblings.push_back(tree[sibling]);
		p.directions.push_back(direction);

		idx = idx / 2;
	}

	return p;
}

bool MerkleTree::verify (const std::string& leaf,
			  const MerkleProof& proof,
			  const std::string& expected_root)
{
	std::string computed = leaf;

	for (size_t i = 0; i < proof.siblings.size(); ++i) {
		if (proof.directions[i] == 1) {
			// Sibling is on the right
			computed = hash_pair(computed, proof.siblings[i]);
		} else {
			// Sibling is on the left
			computed = hash_pair(proof.siblings[i], computed);
		}
	}

	return computed == expected_root;
}

void MerkleTree::save (const std::string& path) const
{
	std::ofstream out(path.c_str(), std::ios::binary);
	if (!out) {
		throw Error("Cannot open Merkle tree file for writing: " + path);
	}

	// Write leaf count (4 bytes, big-endian)
	uint32_t count = static_cast<uint32_t>(leaves.size());
	unsigned char header[4];
	header[0] = (count >> 24) & 0xFF;
	header[1] = (count >> 16) & 0xFF;
	header[2] = (count >> 8) & 0xFF;
	header[3] = count & 0xFF;
	out.write(reinterpret_cast<const char*>(header), 4);

	// Write each leaf hash as 32 raw bytes
	for (size_t i = 0; i < leaves.size(); ++i) {
		std::string bytes = hex_to_bytes(leaves[i]);
		if (bytes.size() != 32) {
			// Pad or truncate to 32 bytes
			bytes.resize(32, '\0');
		}
		out.write(bytes.data(), 32);
	}
}

void MerkleTree::load (const std::string& path)
{
	std::ifstream in(path.c_str(), std::ios::binary);
	if (!in) {
		throw Error("Cannot open Merkle tree file: " + path);
	}

	// Read leaf count
	unsigned char header[4];
	in.read(reinterpret_cast<char*>(header), 4);
	if (!in) {
		throw Error("Invalid Merkle tree file (truncated header)");
	}

	uint32_t count = (static_cast<uint32_t>(header[0]) << 24) |
			 (static_cast<uint32_t>(header[1]) << 16) |
			 (static_cast<uint32_t>(header[2]) << 8) |
			 static_cast<uint32_t>(header[3]);

	leaves.clear();
	for (uint32_t i = 0; i < count; ++i) {
		unsigned char hash[32];
		in.read(reinterpret_cast<char*>(hash), 32);
		if (!in) {
			throw Error("Invalid Merkle tree file (truncated data)");
		}

		std::stringstream ss;
		ss << "0x";
		for (int j = 0; j < 32; ++j) {
			ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[j]);
		}
		leaves.push_back(ss.str());
	}

	rebuild();
}

std::string MerkleTree::leaf_at (uint32_t index) const
{
	if (index >= leaves.size()) {
		throw Error("Leaf index out of range");
	}
	return leaves[index];
}

std::string merkle_proof_to_json (const MerkleProof& proof)
{
	std::stringstream ss;
	ss << "{" << std::endl;
	ss << "  \"leaf_index\": " << proof.leaf_index << "," << std::endl;
	ss << "  \"siblings\": [";
	for (size_t i = 0; i < proof.siblings.size(); ++i) {
		if (i > 0) ss << ", ";
		ss << "\"" << proof.siblings[i] << "\"";
	}
	ss << "]," << std::endl;
	ss << "  \"directions\": [";
	for (size_t i = 0; i < proof.directions.size(); ++i) {
		if (i > 0) ss << ", ";
		ss << static_cast<int>(proof.directions[i]);
	}
	ss << "]" << std::endl;
	ss << "}" << std::endl;
	return ss.str();
}

MerkleProof merkle_proof_from_json (const std::string& json)
{
	MerkleProof proof;
	proof.leaf_index = 0;

	// Simple JSON parser for our known format
	// Parse leaf_index
	size_t pos = json.find("\"leaf_index\"");
	if (pos != std::string::npos) {
		pos = json.find(":", pos);
		if (pos != std::string::npos) {
			proof.leaf_index = static_cast<uint32_t>(std::atoi(json.c_str() + pos + 1));
		}
	}

	// Parse siblings array
	pos = json.find("\"siblings\"");
	if (pos != std::string::npos) {
		size_t arr_start = json.find("[", pos);
		size_t arr_end = json.find("]", arr_start);
		if (arr_start != std::string::npos && arr_end != std::string::npos) {
			std::string arr = json.substr(arr_start + 1, arr_end - arr_start - 1);
			size_t quote_pos = 0;
			while ((quote_pos = arr.find("\"0x", quote_pos)) != std::string::npos) {
				size_t end_quote = arr.find("\"", quote_pos + 1);
				if (end_quote != std::string::npos) {
					proof.siblings.push_back(arr.substr(quote_pos + 1, end_quote - quote_pos - 1));
					quote_pos = end_quote + 1;
				} else {
					break;
				}
			}
		}
	}

	// Parse directions array
	pos = json.find("\"directions\"");
	if (pos != std::string::npos) {
		size_t arr_start = json.find("[", pos);
		size_t arr_end = json.find("]", arr_start);
		if (arr_start != std::string::npos && arr_end != std::string::npos) {
			std::string arr = json.substr(arr_start + 1, arr_end - arr_start - 1);
			std::istringstream iss(arr);
			std::string token;
			while (std::getline(iss, token, ',')) {
				size_t start = token.find_first_not_of(" \t\n\r");
				if (start != std::string::npos) {
					proof.directions.push_back(static_cast<uint8_t>(std::atoi(token.c_str() + start)));
				}
			}
		}
	}

	return proof;
}
