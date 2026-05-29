/*
 * Unit tests for MerkleTree data structure.
 */

#include "catch2/catch.hpp"
#include "trustless_merkle.hpp"
#include "crypto.hpp"
#include <cstdio>
#include <string>

void init_crypto();

TEST_CASE("MerkleTree empty tree", "[merkle]") {
	init_crypto();

	MerkleTree tree;

	SECTION("root is empty for empty tree") {
		CHECK(tree.root().empty());
	}

	SECTION("leaf_count is 0") {
		CHECK(tree.leaf_count() == 0);
	}
}

TEST_CASE("MerkleTree single leaf", "[merkle]") {
	init_crypto();

	MerkleTree tree;
	std::string leaf = MerkleTree::keccak256("test_data_1");
	tree.append(leaf);

	SECTION("has 1 leaf") {
		CHECK(tree.leaf_count() == 1);
	}

	SECTION("root is not empty") {
		CHECK(!tree.root().empty());
	}

	SECTION("can generate proof for leaf 0") {
		MerkleProof proof = tree.proof(0);
		CHECK(proof.leaf_index == 0);
	}

	SECTION("proof verifies correctly") {
		MerkleProof proof = tree.proof(0);
		bool valid = MerkleTree::verify(leaf, proof, tree.root());
		CHECK(valid);
	}
}

TEST_CASE("MerkleTree two leaves", "[merkle]") {
	init_crypto();

	MerkleTree tree;
	std::string leaf0 = MerkleTree::keccak256("data_0");
	std::string leaf1 = MerkleTree::keccak256("data_1");
	tree.append(leaf0);
	tree.append(leaf1);

	SECTION("has 2 leaves") {
		CHECK(tree.leaf_count() == 2);
	}

	SECTION("root equals hash of two leaves") {
		std::string expected = MerkleTree::hash_pair(leaf0, leaf1);
		CHECK(tree.root() == expected);
	}

	SECTION("proof for leaf 0 verifies") {
		MerkleProof proof = tree.proof(0);
		CHECK(MerkleTree::verify(leaf0, proof, tree.root()));
	}

	SECTION("proof for leaf 1 verifies") {
		MerkleProof proof = tree.proof(1);
		CHECK(MerkleTree::verify(leaf1, proof, tree.root()));
	}

	SECTION("wrong leaf fails verification") {
		MerkleProof proof = tree.proof(0);
		CHECK_FALSE(MerkleTree::verify(leaf1, proof, tree.root()));
	}
}

TEST_CASE("MerkleTree four leaves", "[merkle]") {
	init_crypto();

	MerkleTree tree;
	std::string leaves[4];
	for (int i = 0; i < 4; ++i) {
		leaves[i] = MerkleTree::keccak256("leaf_" + std::to_string(i));
		tree.append(leaves[i]);
	}

	SECTION("has 4 leaves") {
		CHECK(tree.leaf_count() == 4);
	}

	SECTION("all proofs verify") {
		for (uint32_t i = 0; i < 4; ++i) {
			MerkleProof proof = tree.proof(i);
			REQUIRE(MerkleTree::verify(leaves[i], proof, tree.root()));
		}
	}

	SECTION("proof depth is 2 for 4 leaves") {
		MerkleProof proof = tree.proof(0);
		CHECK(proof.siblings.size() == 2);
	}
}

TEST_CASE("MerkleTree non-power-of-two leaves", "[merkle]") {
	init_crypto();

	MerkleTree tree;
	std::string leaves[5];
	for (int i = 0; i < 5; ++i) {
		leaves[i] = MerkleTree::keccak256("entry_" + std::to_string(i));
		tree.append(leaves[i]);
	}

	SECTION("has 5 leaves") {
		CHECK(tree.leaf_count() == 5);
	}

	SECTION("all 5 proofs verify") {
		for (uint32_t i = 0; i < 5; ++i) {
			MerkleProof proof = tree.proof(i);
			REQUIRE(MerkleTree::verify(leaves[i], proof, tree.root()));
		}
	}

	SECTION("proof depth is 3 for 5 leaves (padded to 8)") {
		MerkleProof proof = tree.proof(0);
		CHECK(proof.siblings.size() == 3);
	}
}

TEST_CASE("MerkleTree save and load roundtrip", "[merkle]") {
	init_crypto();

	MerkleTree tree;
	for (int i = 0; i < 7; ++i) {
		tree.append(MerkleTree::keccak256("persist_" + std::to_string(i)));
	}

	std::string path = "/tmp/test_merkle_roundtrip.dat";
	tree.save(path);

	MerkleTree loaded;
	loaded.load(path);

	SECTION("same leaf count after load") {
		CHECK(loaded.leaf_count() == tree.leaf_count());
	}

	SECTION("same root after load") {
		CHECK(loaded.root() == tree.root());
	}

	SECTION("proofs still verify after load") {
		for (uint32_t i = 0; i < loaded.leaf_count(); ++i) {
			MerkleProof proof = loaded.proof(i);
			REQUIRE(MerkleTree::verify(loaded.leaf_at(i), proof, loaded.root()));
		}
	}

	// Cleanup
	std::remove(path.c_str());
}

TEST_CASE("MerkleTree leaf_at", "[merkle]") {
	init_crypto();

	MerkleTree tree;
	std::string leaf = MerkleTree::keccak256("specific_leaf");
	tree.append(leaf);

	SECTION("leaf_at returns correct leaf") {
		CHECK(tree.leaf_at(0) == leaf);
	}

	SECTION("leaf_at out of range throws") {
		CHECK_THROWS(tree.leaf_at(1));
	}
}

TEST_CASE("MerkleTree hash_pair deterministic", "[merkle]") {
	init_crypto();

	std::string a = "0x0000000000000000000000000000000000000000000000000000000000000001";
	std::string b = "0x0000000000000000000000000000000000000000000000000000000000000002";

	SECTION("hash_pair is deterministic") {
		CHECK(MerkleTree::hash_pair(a, b) == MerkleTree::hash_pair(a, b));
	}

	SECTION("hash_pair is not commutative") {
		CHECK(MerkleTree::hash_pair(a, b) != MerkleTree::hash_pair(b, a));
	}

	SECTION("hash_pair output starts with 0x") {
		CHECK(MerkleTree::hash_pair(a, b).substr(0, 2) == "0x");
	}

	SECTION("hash_pair output is 66 chars (0x + 64 hex)") {
		CHECK(MerkleTree::hash_pair(a, b).size() == 66);
	}
}

TEST_CASE("MerkleProof JSON serialization roundtrip", "[merkle]") {
	init_crypto();

	MerkleProof original;
	original.leaf_index = 3;
	original.siblings.push_back("0xaaaa000000000000000000000000000000000000000000000000000000000001");
	original.siblings.push_back("0xbbbb000000000000000000000000000000000000000000000000000000000002");
	original.directions.push_back(1);
	original.directions.push_back(0);

	std::string json = merkle_proof_to_json(original);
	MerkleProof restored = merkle_proof_from_json(json);

	SECTION("leaf_index preserved") {
		CHECK(restored.leaf_index == original.leaf_index);
	}

	SECTION("siblings preserved") {
		REQUIRE(restored.siblings.size() == original.siblings.size());
		for (size_t i = 0; i < original.siblings.size(); ++i) {
			CHECK(restored.siblings[i] == original.siblings[i]);
		}
	}

	SECTION("directions preserved") {
		REQUIRE(restored.directions.size() == original.directions.size());
		for (size_t i = 0; i < original.directions.size(); ++i) {
			CHECK(restored.directions[i] == original.directions[i]);
		}
	}
}

TEST_CASE("MerkleTree large tree performance", "[merkle]") {
	init_crypto();

	MerkleTree tree;
	const int N = 100;
	std::string leaves[100];

	for (int i = 0; i < N; ++i) {
		leaves[i] = MerkleTree::keccak256("perf_test_" + std::to_string(i));
		tree.append(leaves[i]);
	}

	SECTION("100-leaf tree has correct count") {
		CHECK(tree.leaf_count() == N);
	}

	SECTION("root is not empty") {
		CHECK(!tree.root().empty());
	}

	SECTION("random proofs verify") {
		// Verify a few random leaves
		uint32_t indices[] = {0, 25, 50, 75, 99};
		for (int i = 0; i < 5; ++i) {
			MerkleProof proof = tree.proof(indices[i]);
			REQUIRE(MerkleTree::verify(leaves[indices[i]], proof, tree.root()));
		}
	}

	SECTION("proof depth is 7 for 100 leaves (padded to 128)") {
		MerkleProof proof = tree.proof(0);
		CHECK(proof.siblings.size() == 7);
	}
}
