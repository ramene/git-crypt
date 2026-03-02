#include "catch2/catch.hpp"
#include "key.hpp"
#include "crypto.hpp"
#include <sstream>
#include <cstring>
#include <cstdio>

TEST_CASE("Key_file generate and stream roundtrip", "[key]") {
	init_crypto();

	SECTION("generate, store, load via streams") {
		Key_file original_key;
		original_key.generate();

		REQUIRE(original_key.is_filled());

		const Key_file::Entry* orig_entry = original_key.get_latest();
		REQUIRE(orig_entry != nullptr);
		REQUIRE(orig_entry->version == 0);

		// Store to string stream
		std::ostringstream out;
		original_key.store(out);
		std::string serialized = out.str();
		REQUIRE(!serialized.empty());

		// Load from string stream
		Key_file loaded_key;
		std::istringstream in(serialized);
		loaded_key.load(in);

		REQUIRE(loaded_key.is_filled());
		const Key_file::Entry* loaded_entry = loaded_key.get_latest();
		REQUIRE(loaded_entry != nullptr);
		REQUIRE(loaded_entry->version == orig_entry->version);
		REQUIRE(std::memcmp(loaded_entry->aes_key, orig_entry->aes_key, AES_KEY_LEN) == 0);
		REQUIRE(std::memcmp(loaded_entry->hmac_key, orig_entry->hmac_key, HMAC_KEY_LEN) == 0);
	}

	SECTION("multiple key versions roundtrip") {
		Key_file original_key;
		original_key.generate(); // version 0
		original_key.generate(); // version 1

		const Key_file::Entry* v0 = original_key.get(0);
		const Key_file::Entry* v1 = original_key.get(1);
		REQUIRE(v0 != nullptr);
		REQUIRE(v1 != nullptr);
		REQUIRE(original_key.latest() == 1);

		// Roundtrip
		std::ostringstream out;
		original_key.store(out);

		Key_file loaded_key;
		std::istringstream in(out.str());
		loaded_key.load(in);

		const Key_file::Entry* lv0 = loaded_key.get(0);
		const Key_file::Entry* lv1 = loaded_key.get(1);
		REQUIRE(lv0 != nullptr);
		REQUIRE(lv1 != nullptr);
		REQUIRE(loaded_key.latest() == 1);
		REQUIRE(std::memcmp(lv0->aes_key, v0->aes_key, AES_KEY_LEN) == 0);
		REQUIRE(std::memcmp(lv1->aes_key, v1->aes_key, AES_KEY_LEN) == 0);
	}

	SECTION("key with name roundtrip") {
		Key_file original_key;
		original_key.set_key_name("test-key");
		original_key.generate();

		std::ostringstream out;
		original_key.store(out);

		Key_file loaded_key;
		std::istringstream in(out.str());
		loaded_key.load(in);

		REQUIRE(loaded_key.get_key_name() != nullptr);
		REQUIRE(std::strcmp(loaded_key.get_key_name(), "test-key") == 0);
	}

	SECTION("file-based roundtrip") {
		Key_file original_key;
		original_key.generate();

		const char* tmpfile = "/tmp/git-crypt-test-key.bin";

		REQUIRE(original_key.store_to_file(tmpfile));

		Key_file loaded_key;
		REQUIRE(loaded_key.load_from_file(tmpfile));

		const Key_file::Entry* orig_entry = original_key.get_latest();
		const Key_file::Entry* loaded_entry = loaded_key.get_latest();
		REQUIRE(loaded_entry != nullptr);
		REQUIRE(std::memcmp(loaded_entry->aes_key, orig_entry->aes_key, AES_KEY_LEN) == 0);
		REQUIRE(std::memcmp(loaded_entry->hmac_key, orig_entry->hmac_key, HMAC_KEY_LEN) == 0);

		std::remove(tmpfile);
	}

	SECTION("store_to_string consistency") {
		Key_file key;
		key.generate();

		std::string s1 = key.store_to_string();
		std::string s2 = key.store_to_string();
		REQUIRE(s1 == s2);
	}

	SECTION("empty key file") {
		Key_file key;
		REQUIRE(key.is_empty());
		REQUIRE(!key.is_filled());
		REQUIRE(key.get_latest() == nullptr);
	}
}

TEST_CASE("validate_key_name", "[key]") {
	SECTION("valid names") {
		REQUIRE(validate_key_name("my-key"));
		REQUIRE(validate_key_name("test_key_123"));
		REQUIRE(validate_key_name("A"));
	}

	SECTION("invalid names") {
		std::string reason;
		REQUIRE(!validate_key_name("", &reason));
		REQUIRE(!validate_key_name("default", &reason));
		REQUIRE(!validate_key_name("has space", &reason));
		REQUIRE(!validate_key_name("has/slash", &reason));
	}
}
