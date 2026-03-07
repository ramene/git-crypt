/*
 * Unit tests for parse_options.cpp
 */

#include "catch2/catch.hpp"
#include "parse_options.hpp"
#include <string>

TEST_CASE("parse_options with no arguments", "[options]") {
	Options_list opts;
	bool flag = false;
	opts.push_back(Option_def("--verbose", &flag));

	const char* argv[] = {"dummy"};
	int result = parse_options(opts, 0, argv);

	CHECK(result == 0);
	CHECK(flag == false);
}

TEST_CASE("parse_options boolean flag", "[options]") {
	bool verbose = false;
	Options_list opts;
	opts.push_back(Option_def("--verbose", &verbose));

	SECTION("flag not present") {
		const char* argv[] = {"somefile"};
		int result = parse_options(opts, 1, argv);
		CHECK(result == 0);
		CHECK(verbose == false);
	}

	SECTION("flag present") {
		const char* argv[] = {"--verbose", "somefile"};
		int result = parse_options(opts, 2, argv);
		CHECK(result == 1);
		CHECK(verbose == true);
	}
}

TEST_CASE("parse_options value flag with separate arg", "[options]") {
	const char* key_name = nullptr;
	Options_list opts;
	opts.push_back(Option_def("--key-name", &key_name));

	const char* argv[] = {"--key-name", "mykey", "somefile"};
	int result = parse_options(opts, 3, argv);

	CHECK(result == 2);
	REQUIRE(key_name != nullptr);
	CHECK(std::string(key_name) == "mykey");
}

TEST_CASE("parse_options value flag with =", "[options]") {
	const char* key_name = nullptr;
	Options_list opts;
	opts.push_back(Option_def("--key-name", &key_name));

	const char* argv[] = {"--key-name=mykey", "somefile"};
	int result = parse_options(opts, 2, argv);

	CHECK(result == 1);
	REQUIRE(key_name != nullptr);
	CHECK(std::string(key_name) == "mykey");
}

TEST_CASE("parse_options -- stops parsing", "[options]") {
	bool verbose = false;
	Options_list opts;
	opts.push_back(Option_def("--verbose", &verbose));

	const char* argv[] = {"--", "--verbose"};
	int result = parse_options(opts, 2, argv);

	CHECK(result == 1);
	CHECK(verbose == false);
}

TEST_CASE("parse_options invalid option throws", "[options]") {
	Options_list opts;
	bool flag = false;
	opts.push_back(Option_def("--verbose", &flag));

	const char* argv[] = {"--unknown"};

	CHECK_THROWS_AS(parse_options(opts, 1, argv), Option_error);
}

TEST_CASE("parse_options value flag missing value throws", "[options]") {
	const char* value = nullptr;
	Options_list opts;
	opts.push_back(Option_def("--output", &value));

	const char* argv[] = {"--output"};

	CHECK_THROWS_AS(parse_options(opts, 1, argv), Option_error);
}

TEST_CASE("parse_options boolean flag with = throws", "[options]") {
	bool flag = false;
	Options_list opts;
	opts.push_back(Option_def("--verbose", &flag));

	const char* argv[] = {"--verbose=yes"};

	CHECK_THROWS_AS(parse_options(opts, 1, argv), Option_error);
}

TEST_CASE("parse_options short flag", "[options]") {
	bool v_flag = false;
	Options_list opts;
	opts.push_back(Option_def("-v", &v_flag));

	const char* argv[] = {"-v", "file"};
	int result = parse_options(opts, 2, argv);

	CHECK(result == 1);
	CHECK(v_flag == true);
}

TEST_CASE("parse_options combined short flags", "[options]") {
	bool a_flag = false;
	bool b_flag = false;
	Options_list opts;
	opts.push_back(Option_def("-a", &a_flag));
	opts.push_back(Option_def("-b", &b_flag));

	const char* argv[] = {"-ab", "file"};
	int result = parse_options(opts, 2, argv);

	CHECK(result == 1);
	CHECK(a_flag == true);
	CHECK(b_flag == true);
}

TEST_CASE("parse_options short flag with value", "[options]") {
	const char* outfile = nullptr;
	Options_list opts;
	opts.push_back(Option_def("-o", &outfile));

	SECTION("value as next arg") {
		const char* argv[] = {"-o", "output.txt", "file"};
		int result = parse_options(opts, 3, argv);
		CHECK(result == 2);
		REQUIRE(outfile != nullptr);
		CHECK(std::string(outfile) == "output.txt");
	}

	SECTION("value attached to flag") {
		const char* argv[] = {"-ooutput.txt", "file"};
		int result = parse_options(opts, 2, argv);
		CHECK(result == 1);
		REQUIRE(outfile != nullptr);
		CHECK(std::string(outfile) == "output.txt");
	}
}

TEST_CASE("parse_options short value flag missing value throws", "[options]") {
	const char* outfile = nullptr;
	Options_list opts;
	opts.push_back(Option_def("-o", &outfile));

	const char* argv[] = {"-o"};

	CHECK_THROWS_AS(parse_options(opts, 1, argv), Option_error);
}

TEST_CASE("parse_options invalid short flag throws", "[options]") {
	Options_list opts;
	bool flag = false;
	opts.push_back(Option_def("-a", &flag));

	const char* argv[] = {"-z"};

	CHECK_THROWS_AS(parse_options(opts, 1, argv), Option_error);
}

TEST_CASE("parse_options multiple long flags", "[options]") {
	bool verbose = false;
	bool force = false;
	const char* key = nullptr;
	Options_list opts;
	opts.push_back(Option_def("--verbose", &verbose));
	opts.push_back(Option_def("--force", &force));
	opts.push_back(Option_def("--key-name", &key));

	const char* argv[] = {"--verbose", "--key-name", "test", "--force", "file"};
	int result = parse_options(opts, 5, argv);

	CHECK(result == 4);
	CHECK(verbose == true);
	CHECK(force == true);
	REQUIRE(key != nullptr);
	CHECK(std::string(key) == "test");
}

TEST_CASE("parse_options stops at non-option argument", "[options]") {
	bool verbose = false;
	Options_list opts;
	opts.push_back(Option_def("--verbose", &verbose));

	const char* argv[] = {"file.txt", "--verbose"};
	int result = parse_options(opts, 2, argv);

	CHECK(result == 0);
	CHECK(verbose == false);
}

TEST_CASE("parse_options empty string arg stops parsing", "[options]") {
	bool verbose = false;
	Options_list opts;
	opts.push_back(Option_def("--verbose", &verbose));

	// A bare "-" (single dash, no option letter) should stop parsing
	// since argv[argi][1] == '\0'
	const char* argv[] = {"-", "--verbose"};
	int result = parse_options(opts, 2, argv);

	CHECK(result == 0);
	CHECK(verbose == false);
}

TEST_CASE("Option_error contains correct fields", "[options]") {
	Options_list opts;

	const char* argv[] = {"--nonexistent"};

	try {
		parse_options(opts, 1, argv);
		FAIL("Expected Option_error");
	} catch (const Option_error& e) {
		CHECK(e.option_name == "--nonexistent");
		CHECK(!e.message.empty());
	}
}
