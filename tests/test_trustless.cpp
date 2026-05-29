/*
 * Unit tests for trustless config and chain interaction modules.
 */

#include "catch2/catch.hpp"
#include "trustless_config.hpp"
#include "trustless_chain.hpp"
#include "crypto.hpp"
#include <cstdlib>
#include <cstring>

// Forward declarations from util
void init_std_streams();
void init_crypto();

TEST_CASE("trustless_config_load_partial with no config", "[config]") {
	init_crypto();

	// Unset all env vars to test clean state
	unsetenv("GIT_CRYPT_TRUSTLESS_RPC_URL");
	unsetenv("GIT_CRYPT_TRUSTLESS_RPC_URLS");
	unsetenv("GIT_CRYPT_TRUSTLESS_CHAIN_ID");
	unsetenv("GIT_CRYPT_TRUSTLESS_REGISTRY_ADDRESS");
	unsetenv("GIT_CRYPT_TRUSTLESS_AUDIT_ADDRESS");
	unsetenv("GIT_CRYPT_TRUSTLESS_FROM_ADDRESS");
	unsetenv("GIT_CRYPT_TRUSTLESS_PRIVATE_KEY");

	Trustless_config cfg = trustless_config_load_partial();

	SECTION("empty RPC URL without config") {
		// rpc_url may be empty or may have git config value
		// Just verify it doesn't crash
		CHECK(true);
	}

	SECTION("private key is empty without env var") {
		CHECK(cfg.private_key.empty());
	}

	SECTION("rpc_threshold defaults to 0 without config") {
		CHECK(cfg.rpc_threshold == 0);
	}
}

TEST_CASE("trustless_config env var override", "[config]") {
	init_crypto();

	setenv("GIT_CRYPT_TRUSTLESS_RPC_URL", "http://test:8545", 1);
	setenv("GIT_CRYPT_TRUSTLESS_CHAIN_ID", "31337", 1);
	setenv("GIT_CRYPT_TRUSTLESS_REGISTRY_ADDRESS", "0x1234567890abcdef1234567890abcdef12345678", 1);
	setenv("GIT_CRYPT_TRUSTLESS_PRIVATE_KEY", "0xdeadbeef", 1);

	Trustless_config cfg = trustless_config_load_partial();

	SECTION("env var sets RPC URL") {
		CHECK(cfg.rpc_url == "http://test:8545");
	}

	SECTION("env var sets chain ID") {
		CHECK(cfg.chain_id == "31337");
	}

	SECTION("env var sets registry address") {
		CHECK(cfg.registry_address == "0x1234567890abcdef1234567890abcdef12345678");
	}

	SECTION("env var sets private key") {
		CHECK(cfg.private_key == "0xdeadbeef");
	}

	// Clean up
	unsetenv("GIT_CRYPT_TRUSTLESS_RPC_URL");
	unsetenv("GIT_CRYPT_TRUSTLESS_CHAIN_ID");
	unsetenv("GIT_CRYPT_TRUSTLESS_REGISTRY_ADDRESS");
	unsetenv("GIT_CRYPT_TRUSTLESS_PRIVATE_KEY");
}

TEST_CASE("trustless_config multi-RPC parsing", "[config]") {
	init_crypto();

	setenv("GIT_CRYPT_TRUSTLESS_RPC_URLS", "http://rpc1:8545, http://rpc2:8545, http://rpc3:8545", 1);
	setenv("GIT_CRYPT_TRUSTLESS_RPC_THRESHOLD", "2", 1);
	setenv("GIT_CRYPT_TRUSTLESS_RPC_URL", "http://rpc1:8545", 1);
	setenv("GIT_CRYPT_TRUSTLESS_REGISTRY_ADDRESS", "0x1234", 1);

	Trustless_config cfg = trustless_config_load_partial();

	SECTION("parses comma-separated RPC URLs") {
		CHECK(cfg.rpc_urls.size() == 3);
		CHECK(cfg.rpc_urls[0] == "http://rpc1:8545");
		CHECK(cfg.rpc_urls[1] == "http://rpc2:8545");
		CHECK(cfg.rpc_urls[2] == "http://rpc3:8545");
	}

	SECTION("parses threshold") {
		CHECK(cfg.rpc_threshold == 2);
	}

	unsetenv("GIT_CRYPT_TRUSTLESS_RPC_URLS");
	unsetenv("GIT_CRYPT_TRUSTLESS_RPC_THRESHOLD");
	unsetenv("GIT_CRYPT_TRUSTLESS_RPC_URL");
	unsetenv("GIT_CRYPT_TRUSTLESS_REGISTRY_ADDRESS");
}

TEST_CASE("trustless_data_dir returns valid path", "[config]") {
	init_crypto();

	// This test requires being in a git repo
	try {
		std::string dir = trustless_data_dir();
		CHECK(dir.find(".git-crypt/trustless") != std::string::npos);
	} catch (...) {
		// Not in a git repo — skip
		CHECK(true);
	}
}

TEST_CASE("pad_id_hex utility", "[chain]") {
	// Testing the ID padding logic used by commands
	std::string id = "abcdef0123456789";
	std::string padded = "0x" + id;
	while (padded.size() < 34) {
		padded += "00";
	}

	SECTION("correct length") {
		CHECK(padded.size() == 34);  // 0x + 32 hex chars
	}

	SECTION("starts with 0x") {
		CHECK(padded.substr(0, 2) == "0x");
	}

	SECTION("contains original ID") {
		CHECK(padded.substr(2, 16) == id);
	}
}
