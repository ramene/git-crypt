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

#ifndef GIT_CRYPT_SHAMIR_HPP
#define GIT_CRYPT_SHAMIR_HPP

#include <vector>
#include <string>
#include <stdint.h>
#include <cstddef>

// A single Shamir share
struct Shamir_share {
	uint8_t		threshold;	// M: minimum shares to reconstruct
	uint8_t		total;		// N: total number of shares
	uint8_t		index;		// Share index (1-based, the x-coordinate)
	std::string	data;		// Share data (same length as secret)

	bool		load_from_file (const char* filename);
	bool		store_to_file (const char* filename) const;
};

// Split a secret into N shares with threshold M
// Returns N Shamir_share objects
std::vector<Shamir_share>	shamir_split (const std::string& secret, uint8_t threshold, uint8_t total);

// Combine M or more shares to reconstruct the secret
// Throws Error if shares are incompatible or insufficient
std::string			shamir_combine (const std::vector<Shamir_share>& shares);

#endif
