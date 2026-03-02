#include "catch2/catch.hpp"
#include "crypto.hpp"
#include <cstring>
#include <sstream>

TEST_CASE("AES-CTR encrypt/decrypt roundtrip", "[crypto]") {
	init_crypto();

	unsigned char key[Aes_ctr_encryptor::KEY_LEN];
	unsigned char nonce[Aes_ctr_encryptor::NONCE_LEN];
	random_bytes(key, sizeof(key));
	random_bytes(nonce, sizeof(nonce));

	SECTION("small buffer roundtrip") {
		const char* original = "Hello, git-crypt!";
		size_t len = std::strlen(original);

		unsigned char ciphertext[64];
		unsigned char plaintext[64];

		Aes_ctr_encryptor encryptor(key, nonce);
		encryptor.process(reinterpret_cast<const unsigned char*>(original), ciphertext, len);

		// Ciphertext should differ from plaintext
		REQUIRE(std::memcmp(original, ciphertext, len) != 0);

		Aes_ctr_decryptor decryptor(key, nonce);
		decryptor.process(ciphertext, plaintext, len);

		REQUIRE(std::memcmp(original, plaintext, len) == 0);
	}

	SECTION("empty buffer roundtrip") {
		unsigned char dummy_in = 0;
		unsigned char dummy_out = 0;

		Aes_ctr_encryptor encryptor(key, nonce);
		encryptor.process(&dummy_in, &dummy_out, 0);
		// No crash is the success condition
		SUCCEED();
	}

	SECTION("large buffer roundtrip") {
		const size_t len = 4096;
		unsigned char original[len];
		unsigned char ciphertext[len];
		unsigned char plaintext[len];

		random_bytes(original, len);

		Aes_ctr_encryptor encryptor(key, nonce);
		encryptor.process(original, ciphertext, len);

		Aes_ctr_decryptor decryptor(key, nonce);
		decryptor.process(ciphertext, plaintext, len);

		REQUIRE(std::memcmp(original, plaintext, len) == 0);
	}

	SECTION("stream encrypt/decrypt roundtrip") {
		const std::string original = "Stream encryption test data for git-crypt roundtrip verification.";

		std::istringstream in_enc(original);
		std::ostringstream out_enc;
		Aes_ctr_encryptor::process_stream(in_enc, out_enc, key, nonce);

		std::string ciphertext = out_enc.str();
		REQUIRE(ciphertext.size() == original.size());
		REQUIRE(ciphertext != original);

		std::istringstream in_dec(ciphertext);
		std::ostringstream out_dec;
		Aes_ctr_decryptor::process_stream(in_dec, out_dec, key, nonce);

		REQUIRE(out_dec.str() == original);
	}

	SECTION("wrong key fails to decrypt") {
		const char* original = "Secret data";
		size_t len = std::strlen(original);

		unsigned char ciphertext[64];
		unsigned char plaintext[64];

		Aes_ctr_encryptor encryptor(key, nonce);
		encryptor.process(reinterpret_cast<const unsigned char*>(original), ciphertext, len);

		unsigned char wrong_key[Aes_ctr_encryptor::KEY_LEN];
		random_bytes(wrong_key, sizeof(wrong_key));

		Aes_ctr_decryptor decryptor(wrong_key, nonce);
		decryptor.process(ciphertext, plaintext, len);

		REQUIRE(std::memcmp(original, plaintext, len) != 0);
	}
}
