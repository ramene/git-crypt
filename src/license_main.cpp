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

#include "git-crypt.hpp"
#include "license_commands.hpp"
#include "commands.hpp"
#include "ssh_signing.hpp"
#include "util.hpp"
#include "crypto.hpp"
#include "parse_options.hpp"
#include <cstring>
#include <iostream>

const char*	argv0;

static void print_usage (std::ostream& out)
{
	out << "Usage: " << argv0 << " COMMAND [ARGS ...]" << std::endl;
	out << std::endl;
	out << "Commands:" << std::endl;
	out << "  init       initialize licensing for this repository" << std::endl;
	out << "  issue      issue a new license to a recipient" << std::endl;
	out << "  verify     verify license signatures" << std::endl;
	out << "  revoke     revoke an issued license" << std::endl;
	out << "  list       list all licenses" << std::endl;
	out << "  show       show license details" << std::endl;
	out << "  anchor     anchor license hash on-chain" << std::endl;
	out << "  import     import a license from file" << std::endl;
	out << "  export     export a license to file" << std::endl;
	out << "  check      check if current user has a valid license" << std::endl;
	out << "  serve      start HTTP license server (x402)" << std::endl;
	out << std::endl;
	out << "See '" << argv0 << " help COMMAND' for more information on a specific command." << std::endl;
}

static void print_version (std::ostream& out)
{
	out << "git-crypt-license " << VERSION << std::endl;
}

static bool help_for_command (const char* command, std::ostream& out)
{
	if (std::strcmp(command, "init") == 0) {
		help_license_init(out);
	} else if (std::strcmp(command, "issue") == 0) {
		help_license_issue(out);
	} else if (std::strcmp(command, "verify") == 0) {
		help_license_verify(out);
	} else if (std::strcmp(command, "revoke") == 0) {
		help_license_revoke(out);
	} else if (std::strcmp(command, "list") == 0) {
		help_license_list(out);
	} else if (std::strcmp(command, "show") == 0) {
		help_license_show(out);
	} else if (std::strcmp(command, "anchor") == 0) {
		help_license_anchor(out);
	} else if (std::strcmp(command, "import") == 0) {
		help_license_import(out);
	} else if (std::strcmp(command, "export") == 0) {
		help_license_export(out);
	} else if (std::strcmp(command, "check") == 0) {
		help_license_check(out);
	} else if (std::strcmp(command, "serve") == 0) {
		help_license_serve(out);
	} else {
		return false;
	}
	return true;
}

static int help (int argc, const char** argv)
{
	if (argc == 0) {
		print_usage(std::cout);
	} else {
		if (!help_for_command(argv[0], std::cout)) {
			std::clog << "Error: '" << argv[0] << "' is not a git-crypt-license command. See '" << argv0 << " help'." << std::endl;
			return 1;
		}
	}
	return 0;
}

static int version (int argc, const char** argv)
{
	print_version(std::cout);
	return 0;
}

int main (int argc, const char** argv)
try {
	argv0 = argv[0];

	init_std_streams();
	init_crypto();

	int		arg_index = 1;
	while (arg_index < argc && argv[arg_index][0] == '-') {
		if (std::strcmp(argv[arg_index], "--help") == 0) {
			print_usage(std::clog);
			return 0;
		} else if (std::strcmp(argv[arg_index], "--version") == 0) {
			print_version(std::clog);
			return 0;
		} else if (std::strcmp(argv[arg_index], "--") == 0) {
			++arg_index;
			break;
		} else {
			std::clog << argv0 << ": " << argv[arg_index] << ": Unknown option" << std::endl;
			print_usage(std::clog);
			return 2;
		}
	}

	argc -= arg_index;
	argv += arg_index;

	if (argc == 0) {
		print_usage(std::clog);
		return 2;
	}

	const char*	command = argv[0];
	--argc;
	++argv;

	try {
		if (std::strcmp(command, "help") == 0) {
			return help(argc, argv);
		}
		if (std::strcmp(command, "version") == 0) {
			return version(argc, argv);
		}
		if (std::strcmp(command, "init") == 0) {
			return license_cmd_init(argc, argv);
		}
		if (std::strcmp(command, "issue") == 0) {
			return license_cmd_issue(argc, argv);
		}
		if (std::strcmp(command, "verify") == 0) {
			return license_cmd_verify(argc, argv);
		}
		if (std::strcmp(command, "revoke") == 0) {
			return license_cmd_revoke(argc, argv);
		}
		if (std::strcmp(command, "list") == 0) {
			return license_cmd_list(argc, argv);
		}
		if (std::strcmp(command, "show") == 0) {
			return license_cmd_show(argc, argv);
		}
		if (std::strcmp(command, "anchor") == 0) {
			return license_cmd_anchor(argc, argv);
		}
		if (std::strcmp(command, "import") == 0) {
			return license_cmd_import(argc, argv);
		}
		if (std::strcmp(command, "export") == 0) {
			return license_cmd_export(argc, argv);
		}
		if (std::strcmp(command, "check") == 0) {
			return license_cmd_check(argc, argv);
		}
		if (std::strcmp(command, "serve") == 0) {
			return license_cmd_serve(argc, argv);
		}
	} catch (const Option_error& e) {
		std::clog << "git-crypt-license: Error: " << e.option_name << ": " << e.message << std::endl;
		help_for_command(command, std::clog);
		return 2;
	}

	std::clog << "Error: '" << command << "' is not a git-crypt-license command. See '" << argv0 << " help'." << std::endl;
	return 2;

} catch (const Error& e) {
	std::cerr << "git-crypt-license: Error: " << e.message << std::endl;
	return 1;
} catch (const Ssh_signing_error& e) {
	std::cerr << "git-crypt-license: SSH signing error: " << e.message << std::endl;
	return 1;
} catch (const System_error& e) {
	std::cerr << "git-crypt-license: System error: " << e.message() << std::endl;
	return 1;
}
