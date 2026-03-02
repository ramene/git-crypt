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

#include "wallet.hpp"
#include "util.hpp"
#include "commands.hpp"
#include "age.hpp"
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

static std::string wallet_get_signer ()
{
	// Configurable via git config wallet.signer
	// Default: "cast" (from foundry toolkit)
	std::string	signer = "cast";
	try {
		signer = get_git_config("wallet.signer");
	} catch (...) {
	}
	return signer;
}

static std::string bytes_to_hex (const unsigned char* data, size_t len)
{
	static const char	hex_chars[] = "0123456789abcdef";
	std::string		result;
	result.reserve(len * 2);
	for (size_t i = 0; i < len; ++i) {
		result += hex_chars[(data[i] >> 4) & 0x0f];
		result += hex_chars[data[i] & 0x0f];
	}
	return result;
}

static unsigned char hex_char_to_nibble (char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return 10 + c - 'a';
	if (c >= 'A' && c <= 'F') return 10 + c - 'A';
	throw Wallet_error("Invalid hex character in signature");
}

static std::vector<unsigned char> hex_to_bytes (const std::string& hex)
{
	std::string	clean_hex = hex;
	// Strip 0x prefix if present
	if (clean_hex.size() >= 2 && clean_hex[0] == '0' && (clean_hex[1] == 'x' || clean_hex[1] == 'X')) {
		clean_hex = clean_hex.substr(2);
	}
	// Strip trailing whitespace/newlines
	while (!clean_hex.empty() && (clean_hex.back() == '\n' || clean_hex.back() == '\r' || clean_hex.back() == ' ')) {
		clean_hex.pop_back();
	}
	if (clean_hex.size() % 2 != 0) {
		throw Wallet_error("Invalid hex string length");
	}
	std::vector<unsigned char>	bytes;
	bytes.reserve(clean_hex.size() / 2);
	for (size_t i = 0; i < clean_hex.size(); i += 2) {
		bytes.push_back((hex_char_to_nibble(clean_hex[i]) << 4) | hex_char_to_nibble(clean_hex[i + 1]));
	}
	return bytes;
}

std::string wallet_challenge_message ()
{
	// Deterministic challenge tied to the repository
	// Use the git remote origin URL or the repo root path as domain separator
	std::string	repo_id;
	try {
		repo_id = get_git_config("remote.origin.url");
	} catch (...) {
		// Fall back to a generic domain
		repo_id = "git-crypt-repository";
	}
	return "git-crypt wallet identity for " + repo_id;
}

std::string wallet_sign_message (const std::string& address, const std::string& message)
{
	// Use the configured signer tool to sign a message
	// Default: cast wallet sign --account ADDRESS "MESSAGE"
	// The signer must output the hex-encoded signature to stdout
	std::string	signer = wallet_get_signer();

	std::vector<std::string>	command;
	if (signer == "cast") {
		// foundry cast: cast wallet sign --account ADDRESS "MESSAGE"
		command.push_back("cast");
		command.push_back("wallet");
		command.push_back("sign");
		command.push_back("--account");
		command.push_back(address);
		command.push_back(message);
	} else {
		// Generic signer: SIGNER sign ADDRESS MESSAGE
		command.push_back(signer);
		command.push_back("sign");
		command.push_back(address);
		command.push_back(message);
	}

	std::stringstream	output;
	if (!successful_exit(exec_command(command, output))) {
		throw Wallet_error("Wallet signing failed. Ensure the signer tool is configured correctly.\n"
				   "Configure with: git config wallet.signer <path-to-signer>");
	}

	std::string	sig = output.str();
	// Trim whitespace
	while (!sig.empty() && (sig.back() == '\n' || sig.back() == '\r' || sig.back() == ' ')) {
		sig.pop_back();
	}
	if (sig.empty()) {
		throw Wallet_error("Wallet signer returned empty signature");
	}
	return sig;
}

std::string wallet_derive_age_identity (const std::string& signature_hex)
{
	// Derive a 32-byte X25519 private key from the signature using SHA-256
	// SHA-256(SHA-256("git-crypt-wallet-key-derivation" || signature_bytes))
	// Double-hash with domain separator for key derivation safety

	std::vector<unsigned char>	sig_bytes = hex_to_bytes(signature_hex);

	// First hash: domain separator + signature
	const std::string		domain = "git-crypt-wallet-key-derivation";
	unsigned char			hash1[SHA256_DIGEST_LENGTH];
	EVP_MD_CTX*			ctx = EVP_MD_CTX_new();
	if (!ctx) {
		throw Wallet_error("Failed to create hash context for key derivation");
	}
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, domain.data(), domain.size());
	EVP_DigestUpdate(ctx, sig_bytes.data(), sig_bytes.size());
	EVP_DigestFinal_ex(ctx, hash1, NULL);

	// Second hash for key stretching
	unsigned char			key_bytes[SHA256_DIGEST_LENGTH];
	EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(ctx, hash1, SHA256_DIGEST_LENGTH);
	EVP_DigestFinal_ex(ctx, key_bytes, NULL);
	EVP_MD_CTX_free(ctx);

	// Clamp the key for X25519 (RFC 7748)
	key_bytes[0] &= 248;
	key_bytes[31] &= 127;
	key_bytes[31] |= 64;

	// Encode as age identity using Bech32 with HRP "AGE-SECRET-KEY-"
	// For simplicity, we write the raw key to a temp file and use age-keygen
	// to validate, or we encode it directly.
	//
	// age identity format: AGE-SECRET-KEY-1<bech32 encoded 32 bytes>
	// We use a hex intermediate: write key bytes, derive via age-keygen --convert
	//
	// However, since Bech32 encoding is non-trivial, we take a practical approach:
	// Write the 32-byte key as a raw identity file that age can consume.
	// age identities are Bech32-encoded, so we shell out to age-keygen if available,
	// or encode using our own minimal Bech32 implementation.

	// Practical approach: use the key bytes as a seed file for age
	// Store as hex and let the command layer use it
	std::string	hex_key = bytes_to_hex(key_bytes, SHA256_DIGEST_LENGTH);
	explicit_memset(key_bytes, 0, SHA256_DIGEST_LENGTH);
	explicit_memset(hash1, 0, SHA256_DIGEST_LENGTH);

	return hex_key;
}

std::string wallet_derive_age_recipient (const std::string& identity_hex)
{
	// Use age-keygen to derive the recipient (public key) from the identity
	// We write the identity hex to a temp file, then use age-keygen --convert

	// Create a temporary identity file in age format
	std::string	identity_file = wallet_write_identity_file(identity_hex);

	// Use age-keygen -y to extract recipient from identity file
	std::vector<std::string>	command;
	command.push_back("age-keygen");
	command.push_back("-y");
	command.push_back(identity_file);

	std::stringstream		output;
	if (!successful_exit(exec_command(command, output))) {
		std::remove(identity_file.c_str());
		throw Wallet_error("Failed to derive age recipient from wallet identity. Is age-keygen installed?");
	}
	std::remove(identity_file.c_str());

	std::string	recipient = output.str();
	while (!recipient.empty() && (recipient.back() == '\n' || recipient.back() == '\r')) {
		recipient.pop_back();
	}
	if (recipient.empty() || recipient.compare(0, 4, "age1") != 0) {
		throw Wallet_error("age-keygen returned invalid recipient");
	}
	return recipient;
}

std::string wallet_recover_address (const std::string& signature_hex, const std::string& message)
{
	// Use cast to recover the signer address from a signature
	// cast wallet verify --address <> "message" sig  OR
	// cast sig recover "message" sig
	std::string	signer = wallet_get_signer();

	if (signer == "cast") {
		std::vector<std::string>	command;
		command.push_back("cast");
		command.push_back("wallet");
		command.push_back("verify");
		command.push_back(message);
		command.push_back(signature_hex);

		std::stringstream	output;
		if (!successful_exit(exec_command(command, output))) {
			throw Wallet_error("Failed to recover address from signature");
		}
		std::string	address = output.str();
		while (!address.empty() && (address.back() == '\n' || address.back() == '\r' || address.back() == ' ')) {
			address.pop_back();
		}
		return address;
	}
	// For non-cast signers, the address is assumed to be provided by the user
	throw Wallet_error("Address recovery requires 'cast' from Foundry toolkit");
}

bool wallet_signer_is_available ()
{
	std::string	signer = wallet_get_signer();
	std::vector<std::string>	command;
	if (signer == "cast") {
		command.push_back("cast");
		command.push_back("--version");
	} else {
		command.push_back(signer);
		command.push_back("--version");
	}
	std::stringstream	output;
	return successful_exit(exec_command(command, output));
}

std::string wallet_write_identity_file (const std::string& identity_hex)
{
	// Convert hex key to raw bytes
	std::vector<unsigned char>	key_bytes = hex_to_bytes(identity_hex);
	if (key_bytes.size() != 32) {
		throw Wallet_error("Invalid identity key length");
	}

	// Write a raw X25519 private key file that age can consume
	// age identity file format: one line starting with AGE-SECRET-KEY-1 (Bech32)
	// Since we don't have Bech32 encoding, we use age-keygen to generate from seed

	// Write raw key bytes to a temp file, use age-keygen to produce identity
	char	tmppath[] = "/tmp/git-crypt-wallet-XXXXXX";
	int	fd = mkstemp(tmppath);
	if (fd < 0) {
		throw Wallet_error("Failed to create temporary file for wallet identity");
	}

	// Write the 32 raw key bytes as an age identity seed
	// age internally uses X25519, and we need to encode in Bech32
	// Approach: pipe raw bytes to age-keygen or write age-compatible format
	//
	// Since age doesn't accept raw keys directly, we use a workaround:
	// Convert to an age identity via the age library format
	// For now, write as a hex seed and use age's plugin mechanism

	// Simplified approach: write the raw 32 bytes to a temp file
	// and use age-keygen --convert to produce a proper identity
	// Actually, age-keygen doesn't have --convert for raw keys.
	//
	// Best approach: implement minimal Bech32 encoding for "age-secret-key-" HRP
	// Bech32 encoding of 32 bytes into the AGE-SECRET-KEY-1... format

	// Bech32 character set
	static const char	bech32_chars[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

	// Bech32 polymod for checksum
	// Adapted from BIP-173 reference implementation
	struct Bech32 {
		static uint32_t polymod (const std::vector<uint8_t>& values) {
			uint32_t	chk = 1;
			for (size_t i = 0; i < values.size(); ++i) {
				uint8_t	b = chk >> 25;
				chk = ((chk & 0x1ffffff) << 5) ^ values[i];
				if (b & 1) chk ^= 0x3b6a57b2;
				if (b & 2) chk ^= 0x26508e6d;
				if (b & 4) chk ^= 0x1ea119fa;
				if (b & 8) chk ^= 0x3d4233dd;
				if (b & 16) chk ^= 0x2a1462b3;
			}
			return chk;
		}

		static std::vector<uint8_t> hrp_expand (const std::string& hrp) {
			std::vector<uint8_t>	ret;
			for (size_t i = 0; i < hrp.size(); ++i) {
				ret.push_back(hrp[i] >> 5);
			}
			ret.push_back(0);
			for (size_t i = 0; i < hrp.size(); ++i) {
				ret.push_back(hrp[i] & 31);
			}
			return ret;
		}

		static std::vector<uint8_t> create_checksum (const std::string& hrp, const std::vector<uint8_t>& data) {
			std::vector<uint8_t>	values = hrp_expand(hrp);
			values.insert(values.end(), data.begin(), data.end());
			for (int i = 0; i < 6; ++i) {
				values.push_back(0);
			}
			uint32_t	pm = polymod(values) ^ 0x3fffffff; // Bech32m constant
			std::vector<uint8_t>	ret(6);
			for (int i = 0; i < 6; ++i) {
				ret[i] = (pm >> (5 * (5 - i))) & 31;
			}
			return ret;
		}

		static std::vector<uint8_t> convert_bits (const unsigned char* data, size_t len, int frombits, int tobits, bool pad) {
			int			acc = 0;
			int			bits = 0;
			std::vector<uint8_t>	ret;
			int			maxv = (1 << tobits) - 1;
			for (size_t i = 0; i < len; ++i) {
				acc = (acc << frombits) | data[i];
				bits += frombits;
				while (bits >= tobits) {
					bits -= tobits;
					ret.push_back((acc >> bits) & maxv);
				}
			}
			if (pad) {
				if (bits > 0) {
					ret.push_back((acc << (tobits - bits)) & maxv);
				}
			}
			return ret;
		}

		static std::string encode (const std::string& hrp, const unsigned char* data, size_t len) {
			std::vector<uint8_t>	data5 = convert_bits(data, len, 8, 5, true);
			std::vector<uint8_t>	checksum = create_checksum(hrp, data5);
			std::string		result = hrp + "1";
			for (size_t i = 0; i < data5.size(); ++i) {
				result += bech32_chars[data5[i]];
			}
			for (size_t i = 0; i < checksum.size(); ++i) {
				result += bech32_chars[checksum[i]];
			}
			return result;
		}
	};

	// Encode as AGE-SECRET-KEY-1...
	std::string	hrp = "age-secret-key-";
	std::string	identity = Bech32::encode(hrp, key_bytes.data(), key_bytes.size());

	// Convert to uppercase as age expects
	std::string	upper_identity;
	for (size_t i = 0; i < identity.size(); ++i) {
		if (identity[i] >= 'a' && identity[i] <= 'z') {
			upper_identity += (identity[i] - 'a' + 'A');
		} else {
			upper_identity += identity[i];
		}
	}

	// Write identity file
	std::string	content = "# wallet-derived age identity\n" + upper_identity + "\n";
	ssize_t		written = write(fd, content.data(), content.size());
	close(fd);

	if (written < 0 || static_cast<size_t>(written) != content.size()) {
		std::remove(tmppath);
		throw Wallet_error("Failed to write wallet identity file");
	}

	// Clear sensitive data
	explicit_memset(&key_bytes[0], 0, key_bytes.size());

	return std::string(tmppath);
}

bool wallet_decrypt_from_file (const std::string& filename, const std::string& identity_hex, std::ostream& output)
{
	// Write identity to temp file, use age -d -i identity_file filename
	std::string	identity_file = wallet_write_identity_file(identity_hex);

	std::string	age_bin = "age";
	try {
		age_bin = get_git_config("age.program");
	} catch (...) {
	}

	std::vector<std::string>	command;
	command.push_back(age_bin);
	command.push_back("-d");
	command.push_back("-i");
	command.push_back(identity_file);
	command.push_back(filename);

	bool	result = successful_exit(exec_command(command, output));
	std::remove(identity_file.c_str());
	return result;
}
