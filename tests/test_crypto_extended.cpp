/*
 * Extended crypto tests: HMAC-SHA1, AES-ECB, random_bytes, edge cases.
 */

#include "catch2/catch.hpp"
#include "crypto.hpp"
#include <cstring>
#include <set>

TEST_CASE("Aes_ecb_encryptor encrypts a block", "[crypto][ecb]") {
	init_crypto();

	unsigned char key[Aes_ecb_encryptor::KEY_LEN];
	random_bytes(key, sizeof(key));

	unsigned char plaintext[Aes_ecb_encryptor::BLOCK_LEN];
	unsigned char ciphertext[Aes_ecb_encryptor::BLOCK_LEN];
	std::memset(plaintext, 0x42, sizeof(plaintext));

	Aes_ecb_encryptor enc(key);
	enc.encrypt(plaintext, ciphertext);

	SECTION("ciphertext differs from plaintext") {
		CHECK(std::memcmp(plaintext, ciphertext, Aes_ecb_encryptor::BLOCK_LEN) != 0);
	}

	SECTION("same key and plaintext produce same ciphertext") {
		unsigned char ciphertext2[Aes_ecb_encryptor::BLOCK_LEN];
		Aes_ecb_encryptor enc2(key);
		enc2.encrypt(plaintext, ciphertext2);
		CHECK(std::memcmp(ciphertext, ciphertext2, Aes_ecb_encryptor::BLOCK_LEN) == 0);
	}

	SECTION("different key produces different ciphertext") {
		unsigned char key2[Aes_ecb_encryptor::KEY_LEN];
		random_bytes(key2, sizeof(key2));

		unsigned char ciphertext2[Aes_ecb_encryptor::BLOCK_LEN];
		Aes_ecb_encryptor enc2(key2);
		enc2.encrypt(plaintext, ciphertext2);
		CHECK(std::memcmp(ciphertext, ciphertext2, Aes_ecb_encryptor::BLOCK_LEN) != 0);
	}
}

TEST_CASE("Hmac_sha1_state basic usage", "[crypto][hmac]") {
	init_crypto();

	unsigned char key[Hmac_sha1_state::KEY_LEN];
	random_bytes(key, sizeof(key));

	const char* message = "Hello, HMAC test!";
	size_t msg_len = std::strlen(message);

	Hmac_sha1_state hmac(key, sizeof(key));
	hmac.add(reinterpret_cast<const unsigned char*>(message), msg_len);

	unsigned char mac[Hmac_sha1_state::LEN];
	hmac.get(mac);

	SECTION("MAC is not all zeros") {
		unsigned char zeros[Hmac_sha1_state::LEN];
		std::memset(zeros, 0, sizeof(zeros));
		CHECK(std::memcmp(mac, zeros, Hmac_sha1_state::LEN) != 0);
	}

	SECTION("same key and message produce same MAC") {
		Hmac_sha1_state hmac2(key, sizeof(key));
		hmac2.add(reinterpret_cast<const unsigned char*>(message), msg_len);
		unsigned char mac2[Hmac_sha1_state::LEN];
		hmac2.get(mac2);
		CHECK(std::memcmp(mac, mac2, Hmac_sha1_state::LEN) == 0);
	}

	SECTION("different message produces different MAC") {
		const char* msg2 = "Different message!";
		Hmac_sha1_state hmac2(key, sizeof(key));
		hmac2.add(reinterpret_cast<const unsigned char*>(msg2), std::strlen(msg2));
		unsigned char mac2[Hmac_sha1_state::LEN];
		hmac2.get(mac2);
		CHECK(std::memcmp(mac, mac2, Hmac_sha1_state::LEN) != 0);
	}

	SECTION("different key produces different MAC") {
		unsigned char key2[Hmac_sha1_state::KEY_LEN];
		random_bytes(key2, sizeof(key2));

		Hmac_sha1_state hmac2(key2, sizeof(key2));
		hmac2.add(reinterpret_cast<const unsigned char*>(message), msg_len);
		unsigned char mac2[Hmac_sha1_state::LEN];
		hmac2.get(mac2);
		CHECK(std::memcmp(mac, mac2, Hmac_sha1_state::LEN) != 0);
	}
}

TEST_CASE("Hmac_sha1_state incremental add", "[crypto][hmac]") {
	init_crypto();

	unsigned char key[Hmac_sha1_state::KEY_LEN];
	random_bytes(key, sizeof(key));

	const char* full_msg = "Hello, HMAC incremental test!";
	size_t full_len = std::strlen(full_msg);

	// Compute MAC in one shot
	Hmac_sha1_state hmac1(key, sizeof(key));
	hmac1.add(reinterpret_cast<const unsigned char*>(full_msg), full_len);
	unsigned char mac1[Hmac_sha1_state::LEN];
	hmac1.get(mac1);

	// Compute MAC in two parts
	Hmac_sha1_state hmac2(key, sizeof(key));
	size_t split = full_len / 2;
	hmac2.add(reinterpret_cast<const unsigned char*>(full_msg), split);
	hmac2.add(reinterpret_cast<const unsigned char*>(full_msg + split), full_len - split);
	unsigned char mac2[Hmac_sha1_state::LEN];
	hmac2.get(mac2);

	CHECK(std::memcmp(mac1, mac2, Hmac_sha1_state::LEN) == 0);
}

TEST_CASE("random_bytes produces unique output", "[crypto][random]") {
	init_crypto();

	// Generate 10 random 32-byte buffers and verify they're all different
	const size_t LEN = 32;
	const int COUNT = 10;
	unsigned char buffers[COUNT][LEN];

	for (int i = 0; i < COUNT; ++i) {
		random_bytes(buffers[i], LEN);
	}

	SECTION("no two buffers are identical") {
		for (int i = 0; i < COUNT; ++i) {
			for (int j = i + 1; j < COUNT; ++j) {
				CHECK(std::memcmp(buffers[i], buffers[j], LEN) != 0);
			}
		}
	}

	SECTION("buffers are not all zeros") {
		unsigned char zeros[LEN];
		std::memset(zeros, 0, LEN);
		for (int i = 0; i < COUNT; ++i) {
			CHECK(std::memcmp(buffers[i], zeros, LEN) != 0);
		}
	}
}

TEST_CASE("AES-CTR different nonces produce different ciphertext", "[crypto][ctr]") {
	init_crypto();

	unsigned char key[Aes_ctr_encryptor::KEY_LEN];
	random_bytes(key, sizeof(key));

	unsigned char nonce1[Aes_ctr_encryptor::NONCE_LEN];
	unsigned char nonce2[Aes_ctr_encryptor::NONCE_LEN];
	random_bytes(nonce1, sizeof(nonce1));
	random_bytes(nonce2, sizeof(nonce2));

	const char* plaintext = "Same data, different nonces";
	size_t len = std::strlen(plaintext);

	unsigned char ct1[64], ct2[64];

	Aes_ctr_encryptor enc1(key, nonce1);
	enc1.process(reinterpret_cast<const unsigned char*>(plaintext), ct1, len);

	Aes_ctr_encryptor enc2(key, nonce2);
	enc2.process(reinterpret_cast<const unsigned char*>(plaintext), ct2, len);

	CHECK(std::memcmp(ct1, ct2, len) != 0);
}

TEST_CASE("AES-CTR single byte roundtrip", "[crypto][ctr]") {
	init_crypto();

	unsigned char key[Aes_ctr_encryptor::KEY_LEN];
	unsigned char nonce[Aes_ctr_encryptor::NONCE_LEN];
	random_bytes(key, sizeof(key));
	random_bytes(nonce, sizeof(nonce));

	unsigned char plain_in = 0xAB;
	unsigned char cipher = 0;
	unsigned char plain_out = 0;

	Aes_ctr_encryptor enc(key, nonce);
	enc.process(&plain_in, &cipher, 1);

	Aes_ctr_decryptor dec(key, nonce);
	dec.process(&cipher, &plain_out, 1);

	CHECK(plain_out == plain_in);
	CHECK(cipher != plain_in);
}

TEST_CASE("AES-CTR block boundary roundtrip", "[crypto][ctr]") {
	init_crypto();

	unsigned char key[Aes_ctr_encryptor::KEY_LEN];
	unsigned char nonce[Aes_ctr_encryptor::NONCE_LEN];
	random_bytes(key, sizeof(key));
	random_bytes(nonce, sizeof(nonce));

	// Test at exact block boundaries: 16, 32, 48 bytes
	for (size_t len : {16, 32, 48}) {
		unsigned char original[48];
		unsigned char ciphertext[48];
		unsigned char recovered[48];

		random_bytes(original, len);

		Aes_ctr_encryptor enc(key, nonce);
		enc.process(original, ciphertext, len);

		Aes_ctr_decryptor dec(key, nonce);
		dec.process(ciphertext, recovered, len);

		REQUIRE(std::memcmp(original, recovered, len) == 0);
	}
}
