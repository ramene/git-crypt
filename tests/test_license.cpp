#include "catch2/catch.hpp"
#include "license.hpp"
#include "license_gate.hpp"
#include "crypto.hpp"
#include <string>
#include <cstring>
#include <algorithm>
#include <ctime>
#include <sstream>
#include <iomanip>

static bool is_hex_string (const std::string& s)
{
	return std::all_of(s.begin(), s.end(), [](char c) {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
	});
}

static std::string future_timestamp (int days)
{
	std::time_t now = std::time(nullptr);
	now += days * 86400;
	std::tm* t = std::gmtime(&now);
	std::ostringstream ss;
	ss << std::put_time(t, "%Y-%m-%dT%H:%M:%SZ");
	return ss.str();
}

static std::string past_timestamp (int days)
{
	std::time_t now = std::time(nullptr);
	now -= days * 86400;
	std::tm* t = std::gmtime(&now);
	std::ostringstream ss;
	ss << std::put_time(t, "%Y-%m-%dT%H:%M:%SZ");
	return ss.str();
}

TEST_CASE("license_generate_id returns 16 hex chars", "[license]") {
	init_crypto();

	std::string id1 = license_generate_id();
	std::string id2 = license_generate_id();

	SECTION("correct length") {
		REQUIRE(id1.size() == 16);
		REQUIRE(id2.size() == 16);
	}

	SECTION("all hex characters") {
		REQUIRE(is_hex_string(id1));
		REQUIRE(is_hex_string(id2));
	}

	SECTION("unique across calls") {
		REQUIRE(id1 != id2);
	}
}

TEST_CASE("License serialize/deserialize roundtrip", "[license]") {
	init_crypto();

	License lic;
	lic.id = "abcdef0123456789";
	lic.licensee_fingerprint = "SHA256:testfingerprintABCD1234";
	lic.licensee_wallet = "0x1234567890abcdef1234567890abcdef12345678";
	lic.scope = "unlock,lock,export-key";
	lic.issued_at = "2025-01-15T12:00:00Z";
	lic.expires_at = "2026-01-15T12:00:00Z";
	lic.status = "active";
	lic.anchor_tx = "0xdeadbeef";
	lic.anchor_rpc = "https://rpc.example.com";

	std::string serialized = license_serialize(lic);
	REQUIRE(!serialized.empty());

	License restored = license_deserialize(serialized);

	CHECK(restored.id == lic.id);
	CHECK(restored.licensee_fingerprint == lic.licensee_fingerprint);
	CHECK(restored.licensee_wallet == lic.licensee_wallet);
	CHECK(restored.scope == lic.scope);
	CHECK(restored.issued_at == lic.issued_at);
	CHECK(restored.expires_at == lic.expires_at);
	CHECK(restored.status == lic.status);
	CHECK(restored.anchor_tx == lic.anchor_tx);
	CHECK(restored.anchor_rpc == lic.anchor_rpc);
}

TEST_CASE("license_scope_contains", "[license]") {
	License lic;
	lic.id = "0000000000000000";
	lic.status = "active";

	SECTION("wildcard matches any operation") {
		lic.scope = "*";
		REQUIRE(license_scope_contains(lic, "unlock"));
		REQUIRE(license_scope_contains(lic, "lock"));
		REQUIRE(license_scope_contains(lic, "export-key"));
		REQUIRE(license_scope_contains(lic, "anything"));
	}

	SECTION("comma-separated scope matches listed operations") {
		lic.scope = "unlock,lock";
		REQUIRE(license_scope_contains(lic, "unlock"));
		REQUIRE(license_scope_contains(lic, "lock"));
		REQUIRE_FALSE(license_scope_contains(lic, "export-key"));
	}

	SECTION("single scope matches only that operation") {
		lic.scope = "unlock";
		REQUIRE(license_scope_contains(lic, "unlock"));
		REQUIRE_FALSE(license_scope_contains(lic, "lock"));
	}
}

TEST_CASE("license_is_valid checks status and expiry", "[license]") {
	License lic;
	lic.id = "0000000000000000";
	lic.licensee_fingerprint = "SHA256:test";
	lic.scope = "*";
	lic.issued_at = past_timestamp(30);

	SECTION("active license with future expiry is valid") {
		lic.status = "active";
		lic.expires_at = future_timestamp(30);
		REQUIRE(license_is_valid(lic));
	}

	SECTION("revoked license is invalid") {
		lic.status = "revoked";
		lic.expires_at = future_timestamp(30);
		REQUIRE_FALSE(license_is_valid(lic));
	}

	SECTION("expired status license is invalid") {
		lic.status = "expired";
		lic.expires_at = future_timestamp(30);
		REQUIRE_FALSE(license_is_valid(lic));
	}

	SECTION("active license with past expiry is invalid") {
		lic.status = "active";
		lic.expires_at = past_timestamp(1);
		REQUIRE_FALSE(license_is_valid(lic));
	}
}

TEST_CASE("license_hash produces consistent SHA-256", "[license]") {
	init_crypto();

	License lic;
	lic.id = "abcdef0123456789";
	lic.licensee_fingerprint = "SHA256:testfingerprintABCD1234";
	lic.licensee_wallet = "";
	lic.scope = "unlock,lock";
	lic.issued_at = "2025-01-15T12:00:00Z";
	lic.expires_at = "2026-01-15T12:00:00Z";
	lic.status = "active";
	lic.anchor_tx = "";
	lic.anchor_rpc = "";

	SECTION("consistent across calls") {
		std::string hash1 = license_hash(lic);
		std::string hash2 = license_hash(lic);
		REQUIRE(hash1 == hash2);
	}

	SECTION("is 64 hex characters") {
		std::string h = license_hash(lic);
		REQUIRE(h.size() == 64);
		REQUIRE(is_hex_string(h));
	}

	SECTION("changes when input changes") {
		std::string h1 = license_hash(lic);
		lic.scope = "*";
		std::string h2 = license_hash(lic);
		REQUIRE(h1 != h2);
	}
}

TEST_CASE("license_check returns 0 when not initialized", "[license][gate]") {
	// When no .git-crypt/licenses/ directory exists, license_check
	// should return 0 for backward compatibility (no licensing = allowed).
	int result = license_check("unlock");
	REQUIRE(result == 0);
}
