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

#ifndef GIT_CRYPT_WALLET_HPP
#define GIT_CRYPT_WALLET_HPP

#include <string>
#include <vector>

struct Wallet_error {
	std::string	message;

	explicit Wallet_error (std::string m) : message(m) { }
};

// Build the deterministic challenge message for signing
std::string	wallet_challenge_message ();

// Sign a message using an external Ethereum wallet signer
// Returns the hex-encoded signature (without 0x prefix)
std::string	wallet_sign_message (const std::string& address, const std::string& message);

// Derive an age X25519 identity (private key) from an Ethereum signature
// Returns the bech32-encoded age identity string (AGE-SECRET-KEY-1...)
std::string	wallet_derive_age_identity (const std::string& signature_hex);

// Derive the age recipient (public key) from an age identity
// Returns the bech32-encoded age recipient string (age1...)
std::string	wallet_derive_age_recipient (const std::string& identity);

// Extract Ethereum address from a hex signature and the signed message
// Returns the checksummed Ethereum address (0x...)
std::string	wallet_recover_address (const std::string& signature_hex, const std::string& message);

// Check if a wallet signer tool is available
bool		wallet_signer_is_available ();

// Write an age identity to a temporary file (for use with age -i)
// Returns the path to the temporary file
std::string	wallet_write_identity_file (const std::string& identity);

// Decrypt an age-encrypted file using a wallet-derived identity
bool		wallet_decrypt_from_file (const std::string& filename, const std::string& identity, std::ostream& output);

#endif
