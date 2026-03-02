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

#include "shamir.hpp"
#include "commands.hpp"
#include "crypto.hpp"
#include "util.hpp"
#include <fstream>
#include <cstring>

// Share file format:
// Bytes 0-12:  "GITCRYPTSHARE" magic (13 bytes)
// Byte 13:     Format version (1)
// Byte 14:     Threshold (M)
// Byte 15:     Total shares (N)
// Byte 16:     Share index (1-based)
// Bytes 17-20: Data length (big-endian uint32)
// Bytes 21+:   Share data

static const char SHARE_MAGIC[] = "GITCRYPTSHARE";
static const uint8_t SHARE_FORMAT_VERSION = 1;

// GF(256) arithmetic with irreducible polynomial x^8 + x^4 + x^3 + x + 1

static uint8_t gf256_add (uint8_t a, uint8_t b)
{
	return a ^ b;
}

static uint8_t gf256_mul (uint8_t a, uint8_t b)
{
	uint8_t	result = 0;
	while (b) {
		if (b & 1) {
			result ^= a;
		}
		bool carry = (a & 0x80) != 0;
		a <<= 1;
		if (carry) {
			a ^= 0x1b;	// x^8 + x^4 + x^3 + x + 1
		}
		b >>= 1;
	}
	return result;
}

static uint8_t gf256_inv (uint8_t a)
{
	if (a == 0) {
		return 0;
	}
	// Fermat's little theorem: a^(-1) = a^(254) in GF(256)
	// 254 = 11111110 in binary
	uint8_t	result = a;			// a^1
	result = gf256_mul(result, result);	// a^2
	result = gf256_mul(result, a);		// a^3
	result = gf256_mul(result, result);	// a^6
	result = gf256_mul(result, a);		// a^7
	result = gf256_mul(result, result);	// a^14
	result = gf256_mul(result, a);		// a^15
	result = gf256_mul(result, result);	// a^30
	result = gf256_mul(result, a);		// a^31
	result = gf256_mul(result, result);	// a^62
	result = gf256_mul(result, a);		// a^63
	result = gf256_mul(result, result);	// a^126
	result = gf256_mul(result, a);		// a^127
	result = gf256_mul(result, result);	// a^254
	return result;
}

static uint8_t gf256_div (uint8_t a, uint8_t b)
{
	return gf256_mul(a, gf256_inv(b));
}

// Evaluate polynomial at point x in GF(256)
// coeffs[0] is the constant term (the secret byte)
static uint8_t eval_poly (const std::vector<uint8_t>& coeffs, uint8_t x)
{
	// Horner's method
	uint8_t	result = 0;
	for (int i = static_cast<int>(coeffs.size()) - 1; i >= 0; --i) {
		result = gf256_add(gf256_mul(result, x), coeffs[i]);
	}
	return result;
}

// Lagrange interpolation at x=0 in GF(256)
// Given points (x_i, y_i), reconstruct f(0) which is the secret byte
static uint8_t lagrange_interpolate (const std::vector<uint8_t>& x_vals, const std::vector<uint8_t>& y_vals)
{
	uint8_t	result = 0;
	size_t	k = x_vals.size();

	for (size_t i = 0; i < k; ++i) {
		// Compute Lagrange basis polynomial L_i(0)
		uint8_t	numerator = 1;
		uint8_t	denominator = 1;
		for (size_t j = 0; j < k; ++j) {
			if (i == j) continue;
			// L_i(0) = product of (0 - x_j) / (x_i - x_j)
			//        = product of x_j / (x_i ^ x_j)  [since -x = x in GF(256)]
			numerator = gf256_mul(numerator, x_vals[j]);
			denominator = gf256_mul(denominator, gf256_add(x_vals[i], x_vals[j]));
		}
		// result += y_i * L_i(0)
		uint8_t	basis = gf256_div(numerator, denominator);
		result = gf256_add(result, gf256_mul(y_vals[i], basis));
	}
	return result;
}


bool Shamir_share::load_from_file (const char* filename)
{
	std::ifstream	in(filename, std::ios::binary);
	if (!in) {
		return false;
	}

	// Read and verify magic
	char	magic[13];
	in.read(magic, 13);
	if (!in || std::memcmp(magic, SHARE_MAGIC, 13) != 0) {
		return false;
	}

	// Read format version
	uint8_t	version;
	in.read(reinterpret_cast<char*>(&version), 1);
	if (!in || version != SHARE_FORMAT_VERSION) {
		return false;
	}

	// Read metadata
	in.read(reinterpret_cast<char*>(&threshold), 1);
	in.read(reinterpret_cast<char*>(&total), 1);
	in.read(reinterpret_cast<char*>(&index), 1);

	// Read data length (big-endian uint32)
	unsigned char	len_bytes[4];
	in.read(reinterpret_cast<char*>(len_bytes), 4);
	if (!in) {
		return false;
	}
	uint32_t	data_len = (static_cast<uint32_t>(len_bytes[0]) << 24) |
				   (static_cast<uint32_t>(len_bytes[1]) << 16) |
				   (static_cast<uint32_t>(len_bytes[2]) << 8) |
				   static_cast<uint32_t>(len_bytes[3]);

	// Read share data
	data.resize(data_len);
	in.read(&data[0], data_len);
	if (!in) {
		return false;
	}

	return true;
}

bool Shamir_share::store_to_file (const char* filename) const
{
	std::ofstream	out(filename, std::ios::binary);
	if (!out) {
		return false;
	}

	// Write magic
	out.write(SHARE_MAGIC, 13);

	// Write format version
	out.write(reinterpret_cast<const char*>(&SHARE_FORMAT_VERSION), 1);

	// Write metadata
	out.write(reinterpret_cast<const char*>(&threshold), 1);
	out.write(reinterpret_cast<const char*>(&total), 1);
	out.write(reinterpret_cast<const char*>(&index), 1);

	// Write data length (big-endian uint32)
	uint32_t	data_len = static_cast<uint32_t>(data.size());
	unsigned char	len_bytes[4];
	len_bytes[0] = static_cast<unsigned char>((data_len >> 24) & 0xFF);
	len_bytes[1] = static_cast<unsigned char>((data_len >> 16) & 0xFF);
	len_bytes[2] = static_cast<unsigned char>((data_len >> 8) & 0xFF);
	len_bytes[3] = static_cast<unsigned char>(data_len & 0xFF);
	out.write(reinterpret_cast<const char*>(len_bytes), 4);

	// Write share data
	out.write(data.data(), data.size());

	out.close();
	return out.good();
}


std::vector<Shamir_share> shamir_split (const std::string& secret, uint8_t threshold, uint8_t total)
{
	if (threshold < 2 || threshold > total || total > 255) {
		throw Error("Invalid Shamir parameters: need 2 <= threshold <= total <= 255");
	}

	std::vector<Shamir_share>	shares(total);

	// Initialize share metadata
	for (uint8_t i = 0; i < total; ++i) {
		shares[i].threshold = threshold;
		shares[i].total = total;
		shares[i].index = i + 1;	// 1-based indices
		shares[i].data.resize(secret.size());
	}

	// For each byte of the secret, create a random polynomial and evaluate
	std::vector<uint8_t>	coeffs(threshold);
	for (size_t pos = 0; pos < secret.size(); ++pos) {
		// coeffs[0] = secret byte (constant term)
		coeffs[0] = static_cast<uint8_t>(secret[pos]);

		// coeffs[1..threshold-1] = random bytes
		random_bytes(&coeffs[1], threshold - 1);

		// Evaluate polynomial at x = 1, 2, ..., total
		for (uint8_t i = 0; i < total; ++i) {
			shares[i].data[pos] = static_cast<char>(eval_poly(coeffs, i + 1));
		}
	}

	// Securely clear coefficients
	explicit_memset(coeffs.data(), 0, coeffs.size());

	return shares;
}

std::string shamir_combine (const std::vector<Shamir_share>& shares)
{
	if (shares.empty()) {
		throw Error("No shares provided");
	}

	uint8_t	threshold = shares[0].threshold;
	size_t	data_len = shares[0].data.size();

	if (shares.size() < threshold) {
		throw Error("Insufficient shares: need at least " + std::to_string(threshold) +
			    " but only " + std::to_string(shares.size()) + " provided");
	}

	// Verify all shares are compatible
	for (size_t i = 1; i < shares.size(); ++i) {
		if (shares[i].threshold != threshold) {
			throw Error("Share threshold mismatch");
		}
		if (shares[i].data.size() != data_len) {
			throw Error("Share data length mismatch");
		}
	}

	// Check for duplicate indices
	for (size_t i = 0; i < shares.size(); ++i) {
		for (size_t j = i + 1; j < shares.size(); ++j) {
			if (shares[i].index == shares[j].index) {
				throw Error("Duplicate share index: " + std::to_string(shares[i].index));
			}
		}
	}

	// Use exactly threshold shares for interpolation
	std::vector<uint8_t>	x_vals(threshold);
	std::vector<uint8_t>	y_vals(threshold);
	for (uint8_t i = 0; i < threshold; ++i) {
		x_vals[i] = shares[i].index;
	}

	// Reconstruct each byte
	std::string	secret(data_len, '\0');
	for (size_t pos = 0; pos < data_len; ++pos) {
		for (uint8_t i = 0; i < threshold; ++i) {
			y_vals[i] = static_cast<uint8_t>(shares[i].data[pos]);
		}
		secret[pos] = static_cast<char>(lagrange_interpolate(x_vals, y_vals));
	}

	return secret;
}
