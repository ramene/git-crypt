/*
 * Copyright 2012, 2014 Andrew Ayer
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

#include "commands.hpp"
#include "crypto.hpp"
#include "util.hpp"
#include "key.hpp"
#include "gpg.hpp"
#include "parse_options.hpp"
#include "coprocess.hpp"
#include <unistd.h>
#include <stdint.h>
#include <algorithm>
#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstddef>
#include <cstring>
#include <cctype>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <exception>
#include <vector>

enum {
	// # of arguments per git checkout call; must be large enough to be efficient but small
	// enough to avoid operating system limits on argument length
	GIT_CHECKOUT_BATCH_SIZE = 100
};

static std::string attribute_name (const char* key_name)
{
	if (key_name) {
		// named key
		return std::string("git-crypt-") + key_name;
	} else {
		// default key
		return "git-crypt";
	}
}

static std::string git_version_string ()
{
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("version");

	std::stringstream		output;
	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git version' failed - is Git installed?");
	}
	std::string			word;
	output >> word; // "git"
	output >> word; // "version"
	output >> word; // "1.7.10.4"
	return word;
}

static std::vector<int> parse_version (const std::string& str)
{
	std::istringstream	in(str);
	std::vector<int>	version;
	std::string		component;
	while (std::getline(in, component, '.')) {
		version.push_back(std::atoi(component.c_str()));
	}
	return version;
}

static const std::vector<int>& git_version ()
{
	static const std::vector<int> version(parse_version(git_version_string()));
	return version;
}

static std::vector<int> make_version (int a, int b, int c)
{
	std::vector<int>	version;
	version.push_back(a);
	version.push_back(b);
	version.push_back(c);
	return version;
}

static void git_config (const std::string& name, const std::string& value)
{
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("config");
	command.push_back(name);
	command.push_back(value);

	if (!successful_exit(exec_command(command))) {
		throw Error("'git config' failed");
	}
}

static bool git_has_config (const std::string& name)
{
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("config");
	command.push_back("--get-all");
	command.push_back(name);

	std::stringstream		output;
	switch (exit_status(exec_command(command, output))) {
		case 0:  return true;
		case 1:  return false;
		default: throw Error("'git config' failed");
	}
}

static void git_deconfig (const std::string& name)
{
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("config");
	command.push_back("--remove-section");
	command.push_back(name);

	if (!successful_exit(exec_command(command))) {
		throw Error("'git config' failed");
	}
}

static void configure_git_filters (const char* key_name)
{
	std::string	escaped_git_crypt_path(escape_shell_arg(our_exe_path()));

	if (key_name) {
		// Note: key_name contains only shell-safe characters so it need not be escaped.
		git_config(std::string("filter.git-crypt-") + key_name + ".smudge",
		           escaped_git_crypt_path + " smudge --key-name=" + key_name);
		git_config(std::string("filter.git-crypt-") + key_name + ".clean",
		           escaped_git_crypt_path + " clean --key-name=" + key_name);
		git_config(std::string("filter.git-crypt-") + key_name + ".required", "true");
		git_config(std::string("diff.git-crypt-") + key_name + ".textconv",
		           escaped_git_crypt_path + " diff --key-name=" + key_name);
	} else {
		git_config("filter.git-crypt.smudge", escaped_git_crypt_path + " smudge");
		git_config("filter.git-crypt.clean", escaped_git_crypt_path + " clean");
		git_config("filter.git-crypt.required", "true");
		git_config("diff.git-crypt.textconv", escaped_git_crypt_path + " diff");
	}
}

static void deconfigure_git_filters (const char* key_name)
{
	// deconfigure the git-crypt filters
	if (git_has_config("filter." + attribute_name(key_name) + ".smudge") ||
			git_has_config("filter." + attribute_name(key_name) + ".clean") ||
			git_has_config("filter." + attribute_name(key_name) + ".required")) {

		git_deconfig("filter." + attribute_name(key_name));
	}

	if (git_has_config("diff." + attribute_name(key_name) + ".textconv")) {
		git_deconfig("diff." + attribute_name(key_name));
	}
}

static bool git_checkout_batch (std::vector<std::string>::const_iterator paths_begin, std::vector<std::string>::const_iterator paths_end)
{
	if (paths_begin == paths_end) {
		return true;
	}

	std::vector<std::string>	command;

	command.push_back("git");
	command.push_back("checkout");
	command.push_back("--");

	for (auto path(paths_begin); path != paths_end; ++path) {
		command.push_back(*path);
	}

	if (!successful_exit(exec_command(command))) {
		return false;
	}

	return true;
}

static bool git_checkout (const std::vector<std::string>& paths)
{
	auto paths_begin(paths.begin());
	while (paths.end() - paths_begin >= GIT_CHECKOUT_BATCH_SIZE) {
		if (!git_checkout_batch(paths_begin, paths_begin + GIT_CHECKOUT_BATCH_SIZE)) {
			return false;
		}
		paths_begin += GIT_CHECKOUT_BATCH_SIZE;
	}
	return git_checkout_batch(paths_begin, paths.end());
}

static bool same_key_name (const char* a, const char* b)
{
	return (!a && !b) || (a && b && std::strcmp(a, b) == 0);
}

static void validate_key_name_or_throw (const char* key_name)
{
	std::string			reason;
	if (!validate_key_name(key_name, &reason)) {
		throw Error(reason);
	}
}

static std::string get_internal_state_path ()
{
	// git rev-parse --git-dir
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("rev-parse");
	command.push_back("--git-dir");

	std::stringstream		output;

	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git rev-parse --git-dir' failed - is this a Git repository?");
	}

	std::string			path;
	std::getline(output, path);
	path += "/git-crypt";

	return path;
}

static std::string get_internal_keys_path (const std::string& internal_state_path)
{
	return internal_state_path + "/keys";
}

static std::string get_internal_keys_path ()
{
	return get_internal_keys_path(get_internal_state_path());
}

static std::string get_internal_key_path (const char* key_name)
{
	std::string		path(get_internal_keys_path());
	path += "/";
	path += key_name ? key_name : "default";

	return path;
}

std::string get_git_config (const std::string& name)
{
	// git config --get
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("config");
	command.push_back("--get");
	command.push_back(name);

	std::stringstream	output;

	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git config' missing value for key '" + name +"'");
	}

	std::string		value;
	std::getline(output, value);

	return value;
}

static std::string get_repo_state_path ()
{
	// git rev-parse --show-toplevel
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("rev-parse");
	command.push_back("--show-toplevel");

	std::stringstream		output;

	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git rev-parse --show-toplevel' failed - is this a Git repository?");
	}

	std::string			path;
	std::getline(output, path);

	if (path.empty()) {
		// could happen for a bare repo
		throw Error("Could not determine Git working tree - is this a non-bare repo?");
	}

	// Check if the repo state dir has been explicitly configured. If so, use that in path construction.
	if (git_has_config("git-crypt.repoStateDir")) {
		std::string		repoStateDir = get_git_config("git-crypt.repoStateDir");

		// The repoStateDir value must always be relative to git work tree to ensure the repoStateDir can be committed
		// along with the remainder of the repository.
		path += '/' + repoStateDir;
	} else {
		// There is no explicitly configured repo state dir configured, so use the default.
		path += "/.git-crypt";
	}

	return path;
}

static std::string get_repo_keys_path (const std::string& repo_state_path)
{
	return repo_state_path + "/keys";
}

static std::string get_repo_keys_path ()
{
	return get_repo_keys_path(get_repo_state_path());
}

static std::string get_path_to_top ()
{
	// git rev-parse --show-cdup
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("rev-parse");
	command.push_back("--show-cdup");

	std::stringstream		output;

	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git rev-parse --show-cdup' failed - is this a Git repository?");
	}

	std::string			path_to_top;
	std::getline(output, path_to_top);

	return path_to_top;
}

static void get_git_status (std::ostream& output)
{
	// git status -uno --porcelain
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("status");
	command.push_back("-uno"); // don't show untracked files
	command.push_back("--porcelain");

	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git status' failed - is this a Git repository?");
	}
}

// returns filter and diff attributes as a pair
static std::pair<std::string, std::string> get_file_attributes (const std::string& filename)
{
	// git check-attr filter diff -- filename
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("check-attr");
	command.push_back("filter");
	command.push_back("diff");
	command.push_back("--");
	command.push_back(filename);

	std::stringstream		output;
	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git check-attr' failed - is this a Git repository?");
	}

	std::string			filter_attr;
	std::string			diff_attr;

	std::string			line;
	// Example output:
	// filename: filter: git-crypt
	// filename: diff: git-crypt
	while (std::getline(output, line)) {
		// filename might contain ": ", so parse line backwards
		// filename: attr_name: attr_value
		//         ^name_pos  ^value_pos
		const std::string::size_type	value_pos(line.rfind(": "));
		if (value_pos == std::string::npos || value_pos == 0) {
			continue;
		}
		const std::string::size_type	name_pos(line.rfind(": ", value_pos - 1));
		if (name_pos == std::string::npos) {
			continue;
		}

		const std::string		attr_name(line.substr(name_pos + 2, value_pos - (name_pos + 2)));
		const std::string		attr_value(line.substr(value_pos + 2));

		if (attr_value != "unspecified" && attr_value != "unset" && attr_value != "set") {
			if (attr_name == "filter") {
				filter_attr = attr_value;
			} else if (attr_name == "diff") {
				diff_attr = attr_value;
			}
		}
	}

	return std::make_pair(filter_attr, diff_attr);
}

// returns filter and diff attributes as a pair
static std::pair<std::string, std::string> get_file_attributes (const std::string& filename, std::ostream& check_attr_stdin, std::istream& check_attr_stdout)
{
	check_attr_stdin << filename << '\0' << std::flush;

	std::string			filter_attr;
	std::string			diff_attr;

	// Example output:
	// filename\0filter\0git-crypt\0filename\0diff\0git-crypt\0
	for (int i = 0; i < 2; ++i) {
		std::string		filename;
		std::string		attr_name;
		std::string		attr_value;
		std::getline(check_attr_stdout, filename, '\0');
		std::getline(check_attr_stdout, attr_name, '\0');
		std::getline(check_attr_stdout, attr_value, '\0');

		if (attr_value != "unspecified" && attr_value != "unset" && attr_value != "set") {
			if (attr_name == "filter") {
				filter_attr = attr_value;
			} else if (attr_name == "diff") {
				diff_attr = attr_value;
			}
		}
	}

	return std::make_pair(filter_attr, diff_attr);
}

static bool check_if_blob_is_encrypted (const std::string& object_id)
{
	// git cat-file blob object_id

	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("cat-file");
	command.push_back("blob");
	command.push_back(object_id);

	// TODO: do this more efficiently - don't read entire command output into buffer, only read what we need
	std::stringstream		output;
	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git cat-file' failed - is this a Git repository?");
	}

	char				header[10];
	output.read(header, sizeof(header));
	return output.gcount() == sizeof(header) && std::memcmp(header, "\0GITCRYPT\0", 10) == 0;
}

static bool check_if_file_is_encrypted (const std::string& filename)
{
	// git ls-files -sz filename
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("ls-files");
	command.push_back("-sz");
	command.push_back("--");
	command.push_back(filename);

	std::stringstream		output;
	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git ls-files' failed - is this a Git repository?");
	}

	if (output.peek() == -1) {
		return false;
	}

	std::string			mode;
	std::string			object_id;
	output >> mode >> object_id;

	return check_if_blob_is_encrypted(object_id);
}

static bool is_git_file_mode (const std::string& mode)
{
	return (std::strtoul(mode.c_str(), nullptr, 8) & 0170000) == 0100000;
}

static void get_encrypted_files (std::vector<std::string>& files, const char* key_name)
{
	// git ls-files -cz -- path_to_top
	std::vector<std::string>	ls_files_command;
	ls_files_command.push_back("git");
	ls_files_command.push_back("ls-files");
	ls_files_command.push_back("-csz");
	ls_files_command.push_back("--");
	const std::string		path_to_top(get_path_to_top());
	if (!path_to_top.empty()) {
		ls_files_command.push_back(path_to_top);
	}

	Coprocess			ls_files;
	std::istream*			ls_files_stdout = ls_files.stdout_pipe();
	ls_files.spawn(ls_files_command);

	Coprocess			check_attr;
	std::ostream*			check_attr_stdin = nullptr;
	std::istream*			check_attr_stdout = nullptr;
	if (git_version() >= make_version(1, 8, 5)) {
		// In Git 1.8.5 (released 27 Nov 2013) and higher, we use a single `git check-attr` process
		// to get the attributes of all files at once.  In prior versions, we have to fork and exec
		// a separate `git check-attr` process for each file, since -z and --stdin aren't supported.
		// In a repository with thousands of files, this results in an almost 100x speedup.
		std::vector<std::string>	check_attr_command;
		check_attr_command.push_back("git");
		check_attr_command.push_back("check-attr");
		check_attr_command.push_back("--stdin");
		check_attr_command.push_back("-z");
		check_attr_command.push_back("filter");
		check_attr_command.push_back("diff");

		check_attr_stdin = check_attr.stdin_pipe();
		check_attr_stdout = check_attr.stdout_pipe();
		check_attr.spawn(check_attr_command);
	}

	while (ls_files_stdout->peek() != -1) {
		std::string		mode;
		std::string		object_id;
		std::string		stage;
		std::string		filename;
		*ls_files_stdout >> mode >> object_id >> stage >> std::ws;
		std::getline(*ls_files_stdout, filename, '\0');

		if (is_git_file_mode(mode)) {
			std::string	filter_attribute;

			if (check_attr_stdin) {
				filter_attribute = get_file_attributes(filename, *check_attr_stdin, *check_attr_stdout).first;
			} else {
				filter_attribute = get_file_attributes(filename).first;
			}

			if (filter_attribute == attribute_name(key_name)) {
				files.push_back(filename);
			}
		}
	}

	if (!successful_exit(ls_files.wait())) {
		throw Error("'git ls-files' failed - is this a Git repository?");
	}

	if (check_attr_stdin) {
		check_attr.close_stdin();
		if (!successful_exit(check_attr.wait())) {
			throw Error("'git check-attr' failed - is this a Git repository?");
		}
	}
}

static void load_key (Key_file& key_file, const char* key_name, const char* key_path =0, const char* legacy_path =0)
{
	if (legacy_path) {
		std::ifstream		key_file_in(legacy_path, std::fstream::binary);
		if (!key_file_in) {
			throw Error(std::string("Unable to open key file: ") + legacy_path);
		}
		key_file.load_legacy(key_file_in);
	} else if (key_path) {
		std::ifstream		key_file_in(key_path, std::fstream::binary);
		if (!key_file_in) {
			throw Error(std::string("Unable to open key file: ") + key_path);
		}
		key_file.load(key_file_in);
	} else {
		std::ifstream		key_file_in(get_internal_key_path(key_name).c_str(), std::fstream::binary);
		if (!key_file_in) {
			std::string	msg("Unable to open key file");
			if (key_name) {
				msg += std::string(" for key '") + key_name + "'";
			}
			msg += " - have you unlocked/initialized this repository yet?";
			throw Error(msg);
		}
		key_file.load(key_file_in);
	}
}

static bool decrypt_repo_key (Key_file& key_file, const char* key_name, uint32_t key_version, const std::vector<std::string>& secret_keys, const std::string& keys_path)
{
	std::exception_ptr gpg_error;

	for (std::vector<std::string>::const_iterator seckey(secret_keys.begin()); seckey != secret_keys.end(); ++seckey) {
		std::ostringstream		path_builder;
		path_builder << keys_path << '/' << (key_name ? key_name : "default") << '/' << key_version << '/' << *seckey << ".gpg";
		std::string			path(path_builder.str());
		if (access(path.c_str(), F_OK) == 0) {
			std::stringstream	decrypted_contents;
			try {
				gpg_decrypt_from_file(path, decrypted_contents);
			} catch (const Gpg_error&) {
				gpg_error = std::current_exception();
				continue;
			}
			Key_file		this_version_key_file;
			this_version_key_file.load(decrypted_contents);
			const Key_file::Entry*	this_version_entry = this_version_key_file.get(key_version);
			if (!this_version_entry) {
				throw Error("GPG-encrypted keyfile is malformed because it does not contain expected key version");
			}
			if (!same_key_name(key_name, this_version_key_file.get_key_name())) {
				throw Error("GPG-encrypted keyfile is malformed because it does not contain expected key name");
			}
			key_file.set_key_name(key_name);
			key_file.add(*this_version_entry);
			return true;
		}
	}

	if (gpg_error) {
		std::rethrow_exception(gpg_error);
	}

	return false;
}

static uint32_t get_latest_key_version (const std::string& key_dir_path)
{
	uint32_t			latest_version = 0;
	bool				found = false;
	std::vector<std::string>	version_dirents;

	if (access(key_dir_path.c_str(), F_OK) == 0) {
		version_dirents = get_directory_contents(key_dir_path.c_str());
	}

	for (std::vector<std::string>::const_iterator vd(version_dirents.begin()); vd != version_dirents.end(); ++vd) {
		// Version directories are numeric
		const char*	s = vd->c_str();
		char*		end = 0;
		unsigned long	v = std::strtoul(s, &end, 10);
		if (end == s || *end != '\0') {
			continue; // not a numeric directory name
		}
		if (!found || v > latest_version) {
			latest_version = static_cast<uint32_t>(v);
			found = true;
		}
	}

	return latest_version;
}

static bool decrypt_repo_keys (std::vector<Key_file>& key_files, const std::vector<std::string>& secret_keys, const std::string& keys_path)
{
	bool				successful = false;
	std::vector<std::string>	dirents;

	if (access(keys_path.c_str(), F_OK) == 0) {
		dirents = get_directory_contents(keys_path.c_str());
	}

	for (std::vector<std::string>::const_iterator dirent(dirents.begin()); dirent != dirents.end(); ++dirent) {
		const char*		key_name = 0;
		if (*dirent != "default") {
			if (!validate_key_name(dirent->c_str())) {
				continue;
			}
			key_name = dirent->c_str();
		}

		std::string		key_dir_path(keys_path + "/" + *dirent);
		uint32_t		key_version = get_latest_key_version(key_dir_path);

		Key_file	key_file;
		if (decrypt_repo_key(key_file, key_name, key_version, secret_keys, keys_path)) {
			key_files.push_back(key_file);
			successful = true;
		}
	}
	return successful;
}

static void encrypt_repo_key (const char* key_name, const Key_file::Entry& key, const std::vector<std::pair<std::string, bool> >& collab_keys, const std::string& keys_path, std::vector<std::string>* new_files)
{
	std::string	key_file_data;
	{
		Key_file this_version_key_file;
		this_version_key_file.set_key_name(key_name);
		this_version_key_file.add(key);
		key_file_data = this_version_key_file.store_to_string();
	}

	for (std::vector<std::pair<std::string, bool> >::const_iterator collab(collab_keys.begin()); collab != collab_keys.end(); ++collab) {
		const std::string&	fingerprint(collab->first);
		const bool		key_is_trusted(collab->second);
		std::ostringstream	path_builder;
		path_builder << keys_path << '/' << (key_name ? key_name : "default") << '/' << key.version << '/' << fingerprint << ".gpg";
		std::string		path(path_builder.str());

		if (access(path.c_str(), F_OK) == 0) {
			continue;
		}

		mkdir_parent(path);
		gpg_encrypt_to_file(path, fingerprint, key_is_trusted, key_file_data.data(), key_file_data.size());
		new_files->push_back(path);
	}
}

static int parse_plumbing_options (const char** key_name, const char** key_file, int argc, const char** argv)
{
	Options_list	options;
	options.push_back(Option_def("-k", key_name));
	options.push_back(Option_def("--key-name", key_name));
	options.push_back(Option_def("--key-file", key_file));

	return parse_options(options, argc, argv);
}

// Encrypt contents of stdin and write to stdout
int clean (int argc, const char** argv)
{
	const char*		key_name = 0;
	const char*		key_path = 0;
	const char*		legacy_key_path = 0;

	int			argi = parse_plumbing_options(&key_name, &key_path, argc, argv);
	if (argc - argi == 0) {
	} else if (!key_name && !key_path && argc - argi == 1) { // Deprecated - for compatibility with pre-0.4
		legacy_key_path = argv[argi];
	} else {
		std::clog << "Usage: git-crypt clean [--key-name=NAME] [--key-file=PATH]" << std::endl;
		return 2;
	}
	Key_file		key_file;
	load_key(key_file, key_name, key_path, legacy_key_path);

	const Key_file::Entry*	key = key_file.get_latest();
	if (!key) {
		std::clog << "git-crypt: error: key file is empty" << std::endl;
		return 1;
	}

	// Read the entire file

	Hmac_sha1_state	hmac(key->hmac_key, HMAC_KEY_LEN); // Calculate the file's SHA1 HMAC as we go
	uint64_t		file_size = 0;	// Keep track of the length, make sure it doesn't get too big
	std::string		file_contents;	// First 8MB or so of the file go here
	temp_fstream		temp_file;	// The rest of the file spills into a temporary file on disk
	temp_file.exceptions(std::fstream::badbit);

	char			buffer[1024];

	while (std::cin && file_size < Aes_ctr_encryptor::MAX_CRYPT_BYTES) {
		std::cin.read(buffer, sizeof(buffer));

		const size_t	bytes_read = std::cin.gcount();

		hmac.add(reinterpret_cast<unsigned char*>(buffer), bytes_read);
		file_size += bytes_read;

		if (file_size <= 8388608) {
			file_contents.append(buffer, bytes_read);
		} else {
			if (!temp_file.is_open()) {
				temp_file.open(std::fstream::in | std::fstream::out | std::fstream::binary | std::fstream::app);
			}
			temp_file.write(buffer, bytes_read);
		}
	}

	// Make sure the file isn't so large we'll overflow the counter value (which would doom security)
	if (file_size >= Aes_ctr_encryptor::MAX_CRYPT_BYTES) {
		std::clog << "git-crypt: error: file too long to encrypt securely" << std::endl;
		return 1;
	}

	// We use an HMAC of the file as the encryption nonce (IV) for CTR mode.
	// By using a hash of the file we ensure that the encryption is
	// deterministic so git doesn't think the file has changed when it really
	// hasn't.  CTR mode with a synthetic IV is provably semantically secure
	// under deterministic CPA as long as the synthetic IV is derived from a
	// secure PRF applied to the message.  Since HMAC-SHA1 is a secure PRF, this
	// encryption scheme is semantically secure under deterministic CPA.
	// 
	// Informally, consider that if a file changes just a tiny bit, the IV will
	// be completely different, resulting in a completely different ciphertext
	// that leaks no information about the similarities of the plaintexts.  Also,
	// since we're using the output from a secure hash function plus a counter
	// as the input to our block cipher, we should never have a situation where
	// two different plaintext blocks get encrypted with the same CTR value.  A
	// nonce will be reused only if the entire file is the same, which leaks no
	// information except that the files are the same.
	//
	// To prevent an attacker from building a dictionary of hash values and then
	// looking up the nonce (which must be stored in the clear to allow for
	// decryption), we use an HMAC as opposed to a straight hash.

	// Note: Hmac_sha1_state::LEN >= Aes_ctr_encryptor::NONCE_LEN

	unsigned char		digest[Hmac_sha1_state::LEN];
	hmac.get(digest);

	// Write a header that...
	std::cout.write("\0GITCRYPT\0", 10); // ...identifies this as an encrypted file
	std::cout.write(reinterpret_cast<char*>(digest), Aes_ctr_encryptor::NONCE_LEN); // ...includes the nonce

	// Now encrypt the file and write to stdout
	Aes_ctr_encryptor	aes(key->aes_key, digest);

	// First read from the in-memory copy
	const unsigned char*	file_data = reinterpret_cast<const unsigned char*>(file_contents.data());
	size_t			file_data_len = file_contents.size();
	while (file_data_len > 0) {
		const size_t	buffer_len = std::min(sizeof(buffer), file_data_len);
		aes.process(file_data, reinterpret_cast<unsigned char*>(buffer), buffer_len);
		std::cout.write(buffer, buffer_len);
		file_data += buffer_len;
		file_data_len -= buffer_len;
	}

	// Then read from the temporary file if applicable
	if (temp_file.is_open()) {
		temp_file.seekg(0);
		while (temp_file.peek() != -1) {
			temp_file.read(buffer, sizeof(buffer));

			const size_t	buffer_len = temp_file.gcount();

			aes.process(reinterpret_cast<unsigned char*>(buffer),
			            reinterpret_cast<unsigned char*>(buffer),
			            buffer_len);
			std::cout.write(buffer, buffer_len);
		}
	}

	return 0;
}

static int decrypt_file_to_stdout (const Key_file& key_file, const unsigned char* header, std::istream& in)
{
	const unsigned char*	nonce = header + 10;
	uint32_t		key_version = 0; // TODO: get the version from the file header

	const Key_file::Entry*	key = key_file.get(key_version);
	if (!key) {
		std::clog << "git-crypt: error: key version " << key_version << " not available - please unlock with the latest version of the key." << std::endl;
		return 1;
	}

	Aes_ctr_decryptor	aes(key->aes_key, nonce);
	Hmac_sha1_state		hmac(key->hmac_key, HMAC_KEY_LEN);
	while (in) {
		unsigned char	buffer[1024];
		in.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
		aes.process(buffer, buffer, in.gcount());
		hmac.add(buffer, in.gcount());
		std::cout.write(reinterpret_cast<char*>(buffer), in.gcount());
	}

	unsigned char		digest[Hmac_sha1_state::LEN];
	hmac.get(digest);
	if (!leakless_equals(digest, nonce, Aes_ctr_decryptor::NONCE_LEN)) {
		std::clog << "git-crypt: error: encrypted file has been tampered with!" << std::endl;
		// Although we've already written the tampered file to stdout, exiting
		// with a non-zero status will tell git the file has not been filtered,
		// so git will not replace it.
		return 1;
	}

	return 0;
}

// Decrypt contents of stdin and write to stdout
int smudge (int argc, const char** argv)
{
	const char*		key_name = 0;
	const char*		key_path = 0;
	const char*		legacy_key_path = 0;

	int			argi = parse_plumbing_options(&key_name, &key_path, argc, argv);
	if (argc - argi == 0) {
	} else if (!key_name && !key_path && argc - argi == 1) { // Deprecated - for compatibility with pre-0.4
		legacy_key_path = argv[argi];
	} else {
		std::clog << "Usage: git-crypt smudge [--key-name=NAME] [--key-file=PATH]" << std::endl;
		return 2;
	}
	Key_file		key_file;
	load_key(key_file, key_name, key_path, legacy_key_path);

	// Read the header to get the nonce and make sure it's actually encrypted
	unsigned char		header[10 + Aes_ctr_decryptor::NONCE_LEN];
	std::cin.read(reinterpret_cast<char*>(header), sizeof(header));
	if (std::cin.gcount() != sizeof(header) || std::memcmp(header, "\0GITCRYPT\0", 10) != 0) {
		// File not encrypted - just copy it out to stdout
		std::clog << "git-crypt: Warning: file not encrypted" << std::endl;
		std::clog << "git-crypt: Run 'git-crypt status' to make sure all files are properly encrypted." << std::endl;
		std::clog << "git-crypt: If 'git-crypt status' reports no problems, then an older version of" << std::endl;
		std::clog << "git-crypt: this file may be unencrypted in the repository's history.  If this" << std::endl;
		std::clog << "git-crypt: file contains sensitive information, you can use 'git filter-branch'" << std::endl;
		std::clog << "git-crypt: to remove its old versions from the history." << std::endl;
		std::cout.write(reinterpret_cast<char*>(header), std::cin.gcount()); // include the bytes which we already read
		std::cout << std::cin.rdbuf();
		return 0;
	}

	return decrypt_file_to_stdout(key_file, header, std::cin);
}

int diff (int argc, const char** argv)
{
	const char*		key_name = 0;
	const char*		key_path = 0;
	const char*		filename = 0;
	const char*		legacy_key_path = 0;

	int			argi = parse_plumbing_options(&key_name, &key_path, argc, argv);
	if (argc - argi == 1) {
		filename = argv[argi];
	} else if (!key_name && !key_path && argc - argi == 2) { // Deprecated - for compatibility with pre-0.4
		legacy_key_path = argv[argi];
		filename = argv[argi + 1];
	} else {
		std::clog << "Usage: git-crypt diff [--key-name=NAME] [--key-file=PATH] FILENAME" << std::endl;
		return 2;
	}
	Key_file		key_file;
	load_key(key_file, key_name, key_path, legacy_key_path);

	// Open the file
	std::ifstream		in(filename, std::fstream::binary);
	if (!in) {
		std::clog << "git-crypt: " << filename << ": unable to open for reading" << std::endl;
		return 1;
	}
	in.exceptions(std::fstream::badbit);

	// Read the header to get the nonce and determine if it's actually encrypted
	unsigned char		header[10 + Aes_ctr_decryptor::NONCE_LEN];
	in.read(reinterpret_cast<char*>(header), sizeof(header));
	if (in.gcount() != sizeof(header) || std::memcmp(header, "\0GITCRYPT\0", 10) != 0) {
		// File not encrypted - just copy it out to stdout
		std::cout.write(reinterpret_cast<char*>(header), in.gcount()); // include the bytes which we already read
		std::cout << in.rdbuf();
		return 0;
	}

	// Go ahead and decrypt it
	return decrypt_file_to_stdout(key_file, header, in);
}

void help_init (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt init [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    -k, --key-name KEYNAME      Initialize the given key, instead of the default" << std::endl;
	out << "    -f, --force                 Force re-initialization (regenerate key)" << std::endl;
	out << std::endl;
}

int init (int argc, const char** argv)
{
	const char*	key_name = 0;
	bool		force = false;
	Options_list	options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("-f", &force));
	options.push_back(Option_def("--force", &force));

	int		argi = parse_options(options, argc, argv);

	if (!key_name && !force && argc - argi == 1) {
		std::clog << "Warning: 'git-crypt init' with a key file is deprecated as of git-crypt 0.4" << std::endl;
		std::clog << "and will be removed in a future release. Please get in the habit of using" << std::endl;
		std::clog << "'git-crypt unlock KEYFILE' instead." << std::endl;
		return unlock(argc, argv);
	}
	if (argc - argi != 0) {
		std::clog << "Error: git-crypt init takes no arguments" << std::endl;
		help_init(std::clog);
		return 2;
	}

	if (key_name) {
		validate_key_name_or_throw(key_name);
	}

	std::string		internal_key_path(get_internal_key_path(key_name));
	if (access(internal_key_path.c_str(), F_OK) == 0) {
		if (!force) {
			std::clog << "Error: this repository has already been initialized with git-crypt";
			if (key_name) {
				std::clog << " (key '" << key_name << "')";
			}
			std::clog << "." << std::endl;
			std::clog << "Use 'git-crypt init --force' to re-initialize with a new key." << std::endl;
			return 1;
		}
		std::clog << "Warning: re-initializing git-crypt";
		if (key_name) {
			std::clog << " (key '" << key_name << "')";
		}
		std::clog << " - generating new key." << std::endl;
	}

	// 1. Generate a key and install it
	std::clog << "Generating key..." << std::endl;
	Key_file		key_file;
	key_file.set_key_name(key_name);
	key_file.generate();

	mkdir_parent(internal_key_path);
	if (!key_file.store_to_file(internal_key_path.c_str())) {
		std::clog << "Error: " << internal_key_path << ": unable to write key file" << std::endl;
		return 1;
	}

	// 2. Configure git for git-crypt
	configure_git_filters(key_name);

	return 0;
}

void help_unlock (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt unlock" << std::endl;
	out << "   or: git-crypt unlock KEY_FILE ..." << std::endl;
}
int unlock (int argc, const char** argv)
{
	// 1. Make sure working directory is clean (ignoring untracked files)
	// We do this because we check out files later, and we don't want the
	// user to lose any changes.  (TODO: only care if encrypted files are
	// modified, since we only check out encrypted files)

	// Running 'git status' also serves as a check that the Git repo is accessible.

	std::stringstream	status_output;
	get_git_status(status_output);
	if (status_output.peek() != -1) {
		std::clog << "Error: Working directory not clean." << std::endl;
		std::clog << "Please commit your changes or 'git stash' them before running 'git-crypt unlock'." << std::endl;
		return 1;
	}

	// 2. Load the key(s)
	std::vector<Key_file>	key_files;
	if (argc > 0) {
		// Read from the symmetric key file(s)

		for (int argi = 0; argi < argc; ++argi) {
			const char*	symmetric_key_file = argv[argi];
			Key_file	key_file;

			try {
				if (std::strcmp(symmetric_key_file, "-") == 0) {
					key_file.load(std::cin);
				} else {
					if (!key_file.load_from_file(symmetric_key_file)) {
						std::clog << "Error: " << symmetric_key_file << ": unable to read key file" << std::endl;
						return 1;
					}
				}
			} catch (Key_file::Incompatible) {
				std::clog << "Error: " << symmetric_key_file << " is in an incompatible format" << std::endl;
				std::clog << "Please upgrade to a newer version of git-crypt." << std::endl;
				return 1;
			} catch (Key_file::Malformed) {
				std::clog << "Error: " << symmetric_key_file << ": not a valid git-crypt key file" << std::endl;
				std::clog << "If this key was created prior to git-crypt 0.4, you need to migrate it" << std::endl;
				std::clog << "by running 'git-crypt migrate-key /path/to/old_key /path/to/migrated_key'." << std::endl;
				return 1;
			}

			key_files.push_back(key_file);
		}
	} else {
		// Decrypt GPG key from root of repo
		std::string			repo_keys_path(get_repo_keys_path());
		std::vector<std::string>	gpg_secret_keys(gpg_list_secret_keys());
		// TODO: command-line option to specify the precise secret key to use
		// TODO: command line option to only unlock specific key instead of all of them
		// TODO: avoid decrypting repo keys which are already unlocked in the .git directory
		if (!decrypt_repo_keys(key_files, gpg_secret_keys, repo_keys_path)) {
			std::clog << "Error: no GPG secret key available to unlock this repository." << std::endl;
			std::clog << "To unlock with a shared symmetric key instead, specify the path to the symmetric key as an argument to 'git-crypt unlock'." << std::endl;
			// TODO std::clog << "To see a list of GPG keys authorized to unlock this repository, run 'git-crypt ls-gpg-users'." << std::endl;
			return 1;
		}
	}


	// 3. Install the key(s) and configure the git filters
	std::vector<std::string>	encrypted_files;
	for (std::vector<Key_file>::iterator key_file(key_files.begin()); key_file != key_files.end(); ++key_file) {
		std::string		internal_key_path(get_internal_key_path(key_file->get_key_name()));
		// TODO: croak if internal_key_path already exists???
		mkdir_parent(internal_key_path);
		if (!key_file->store_to_file(internal_key_path.c_str())) {
			std::clog << "Error: " << internal_key_path << ": unable to write key file" << std::endl;
			return 1;
		}

		configure_git_filters(key_file->get_key_name());
		get_encrypted_files(encrypted_files, key_file->get_key_name());
	}

	// 4. Check out the files that are currently encrypted.
	// Git won't check out a file if its mtime hasn't changed, so touch every file first.
	for (std::vector<std::string>::const_iterator file(encrypted_files.begin()); file != encrypted_files.end(); ++file) {
		touch_file(*file);
	}
	if (!git_checkout(encrypted_files)) {
		std::clog << "Error: 'git checkout' failed" << std::endl;
		std::clog << "git-crypt has been set up but existing encrypted files have not been decrypted" << std::endl;
		return 1;
	}

	return 0;
}

void help_lock (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt lock [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    -a, --all                Lock all keys, instead of just the default" << std::endl;
	out << "    -k, --key-name KEYNAME   Lock the given key, instead of the default" << std::endl;
	out << "    -f, --force              Lock even if unclean (you may lose uncommited work)" << std::endl;
	out << std::endl;
}
int lock (int argc, const char** argv)
{
	const char*	key_name = 0;
	bool		all_keys = false;
	bool		force = false;
	Options_list	options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("-a", &all_keys));
	options.push_back(Option_def("--all", &all_keys));
	options.push_back(Option_def("-f", &force));
	options.push_back(Option_def("--force", &force));

	int			argi = parse_options(options, argc, argv);

	if (argc - argi != 0) {
		std::clog << "Error: git-crypt lock takes no arguments" << std::endl;
		help_lock(std::clog);
		return 2;
	}

	if (all_keys && key_name) {
		std::clog << "Error: -k and --all options are mutually exclusive" << std::endl;
		return 2;
	}

	// 1. Make sure working directory is clean (ignoring untracked files)
	// We do this because we check out files later, and we don't want the
	// user to lose any changes.  (TODO: only care if encrypted files are
	// modified, since we only check out encrypted files)

	// Running 'git status' also serves as a check that the Git repo is accessible.

	std::stringstream	status_output;
	get_git_status(status_output);
	if (!force && status_output.peek() != -1) {
		std::clog << "Error: Working directory not clean." << std::endl;
		std::clog << "Please commit your changes or 'git stash' them before running 'git-crypt lock'." << std::endl;
		std::clog << "Or, use 'git-crypt lock --force' and possibly lose uncommitted changes." << std::endl;
		return 1;
	}

	// 2. deconfigure the git filters and remove decrypted keys
	std::vector<std::string>	encrypted_files;
	if (all_keys) {
		// deconfigure for all keys
		std::vector<std::string> dirents = get_directory_contents(get_internal_keys_path().c_str());

		for (std::vector<std::string>::const_iterator dirent(dirents.begin()); dirent != dirents.end(); ++dirent) {
			const char* this_key_name = (*dirent == "default" ? 0 : dirent->c_str());
			remove_file(get_internal_key_path(this_key_name));
			deconfigure_git_filters(this_key_name);
			get_encrypted_files(encrypted_files, this_key_name);
		}
	} else {
		// just handle the given key
		std::string	internal_key_path(get_internal_key_path(key_name));
		if (access(internal_key_path.c_str(), F_OK) == -1 && errno == ENOENT) {
			std::clog << "Error: this repository is already locked";
			if (key_name) {
				std::clog << " with key '" << key_name << "'";
			}
			std::clog << "." << std::endl;
			return 1;
		}

		remove_file(internal_key_path);
		deconfigure_git_filters(key_name);
		get_encrypted_files(encrypted_files, key_name);
	}

	// 3. Check out the files that are currently decrypted but should be encrypted.
	// Git won't check out a file if its mtime hasn't changed, so touch every file first.
	for (std::vector<std::string>::const_iterator file(encrypted_files.begin()); file != encrypted_files.end(); ++file) {
		touch_file(*file);
	}
	if (!git_checkout(encrypted_files)) {
		std::clog << "Error: 'git checkout' failed" << std::endl;
		std::clog << "git-crypt has been locked up but existing decrypted files have not been encrypted" << std::endl;
		return 1;
	}

	return 0;
}

void help_add_gpg_user (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt add-gpg-user [OPTIONS] GPG_USER_ID ..." << std::endl;
	out << std::endl;
	out << "    -k, --key-name KEYNAME      Add GPG user to given key, instead of default" << std::endl;
	out << "    -n, --no-commit             Don't automatically commit" << std::endl;
	out << "    --trusted                   Assume the GPG user IDs are trusted" << std::endl;
	out << std::endl;
}
int add_gpg_user (int argc, const char** argv)
{
	const char*		key_name = 0;
	bool			no_commit = false;
	bool			trusted = false;
	Options_list		options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("-n", &no_commit));
	options.push_back(Option_def("--no-commit", &no_commit));
	options.push_back(Option_def("--trusted", &trusted));

	int			argi = parse_options(options, argc, argv);
	if (argc - argi == 0) {
		std::clog << "Error: no GPG user ID specified" << std::endl;
		help_add_gpg_user(std::clog);
		return 2;
	}

	// build a list of key fingerprints, and whether the key is trusted, for every collaborator specified on the command line
	std::vector<std::pair<std::string, bool> >	collab_keys;

	for (int i = argi; i < argc; ++i) {
		std::vector<std::string> keys(gpg_lookup_key(argv[i]));
		if (keys.empty()) {
			std::clog << "Error: public key for '" << argv[i] << "' not found in your GPG keyring" << std::endl;
			return 1;
		}
		if (keys.size() > 1) {
			std::clog << "Error: more than one public key matches '" << argv[i] << "' - please be more specific" << std::endl;
			return 1;
		}

		const bool is_full_fingerprint(std::strncmp(argv[i], "0x", 2) == 0 && std::strlen(argv[i]) == 42);
		collab_keys.push_back(std::make_pair(keys[0], trusted || is_full_fingerprint));
	}

	// TODO: have a retroactive option to grant access to all key versions, not just the most recent
	Key_file			key_file;
	load_key(key_file, key_name);
	const Key_file::Entry*		key = key_file.get_latest();
	if (!key) {
		std::clog << "Error: key file is empty";
		if (key_name) {
			std::clog << " (key '" << key_name << "')";
		}
		std::clog << std::endl;
		return 1;
	}

	const std::string		state_path(get_repo_state_path());
	std::vector<std::string>	new_files;

	encrypt_repo_key(key_name, *key, collab_keys, get_repo_keys_path(state_path), &new_files);

	// Add a .gitatributes file to the repo state directory to prevent files in it from being encrypted.
	const std::string		state_gitattributes_path(state_path + "/.gitattributes");
	if (access(state_gitattributes_path.c_str(), F_OK) != 0) {
		std::ofstream		state_gitattributes_file(state_gitattributes_path.c_str());
		//                          |--------------------------------------------------------------------------------| 80 chars
		state_gitattributes_file << "# Do not edit this file.  To specify the files to encrypt, create your own\n";
		state_gitattributes_file << "# .gitattributes file in the directory where your files are.\n";
		state_gitattributes_file << "* !filter !diff\n";
		state_gitattributes_file << "*.gpg binary\n";
		state_gitattributes_file.close();
		if (!state_gitattributes_file) {
			std::clog << "Error: unable to write " << state_gitattributes_path << std::endl;
			return 1;
		}
		new_files.push_back(state_gitattributes_path);
	}

	// add/commit the new files
	if (!new_files.empty()) {
		// git add NEW_FILE ...
		std::vector<std::string>	command;
		command.push_back("git");
		command.push_back("add");
		command.push_back("--");
		command.insert(command.end(), new_files.begin(), new_files.end());
		if (!successful_exit(exec_command(command))) {
			std::clog << "Error: 'git add' failed" << std::endl;
			return 1;
		}

		// git commit ...
		if (!no_commit) {
			std::ostringstream	commit_message_builder;
			commit_message_builder << "Add " << collab_keys.size() << " git-crypt collaborator" << (collab_keys.size() != 1 ? "s" : "");
			if (key_name) {
				commit_message_builder << " for key '" << key_name << "'";
			}
			commit_message_builder << "\n\nNew collaborators:\n\n";
			for (std::vector<std::pair<std::string, bool> >::const_iterator collab(collab_keys.begin()); collab != collab_keys.end(); ++collab) {
				commit_message_builder << "    " << collab->first << '\n';
				commit_message_builder << "        " << gpg_get_uid(collab->first) << '\n';
			}

			// git commit -m MESSAGE NEW_FILE ...
			command.clear();
			command.push_back("git");
			command.push_back("commit");
			command.push_back("-m");
			command.push_back(commit_message_builder.str());
			command.push_back("--");
			command.insert(command.end(), new_files.begin(), new_files.end());

			if (!successful_exit(exec_command(command))) {
				std::clog << "Error: 'git commit' failed" << std::endl;
				return 1;
			}
		}
	}

	return 0;
}

void help_rm_gpg_user (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt rm-gpg-user [OPTIONS] GPG_USER_ID ..." << std::endl;
	out << std::endl;
	out << "    -k, --key-name KEYNAME      Remove user from given key, instead of default" << std::endl;
	out << "    -n, --no-commit             Don't automatically commit" << std::endl;
	out << std::endl;
}
int rm_gpg_user (int argc, const char** argv)
{
	const char*		key_name = 0;
	bool			no_commit = false;
	Options_list		options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("-n", &no_commit));
	options.push_back(Option_def("--no-commit", &no_commit));

	int			argi = parse_options(options, argc, argv);
	if (argc - argi == 0) {
		std::clog << "Error: no GPG user ID specified" << std::endl;
		help_rm_gpg_user(std::clog);
		return 2;
	}

	if (key_name) {
		validate_key_name_or_throw(key_name);
	}

	// Resolve each user ID to a fingerprint
	std::vector<std::string>	fingerprints;
	for (int i = argi; i < argc; ++i) {
		std::vector<std::string>	keys(gpg_lookup_key(argv[i]));
		if (keys.empty()) {
			std::clog << "Error: public key for '" << argv[i] << "' not found in your GPG keyring" << std::endl;
			return 1;
		}
		if (keys.size() > 1) {
			std::clog << "Error: more than one public key matches '" << argv[i] << "' - please be more specific" << std::endl;
			return 1;
		}
		fingerprints.push_back(keys[0]);
	}

	const std::string		repo_keys_path(get_repo_keys_path());
	const std::string		key_dir_name(key_name ? key_name : "default");
	const std::string		key_path(repo_keys_path + "/" + key_dir_name);

	if (access(key_path.c_str(), F_OK) != 0) {
		std::clog << "Error: key directory not found: " << key_path << std::endl;
		return 1;
	}

	// Iterate over version subdirectories under the key directory
	std::vector<std::string>	version_dirs(get_directory_contents(key_path.c_str()));
	std::vector<std::string>	removed_files;

	for (std::vector<std::string>::const_iterator fingerprint(fingerprints.begin()); fingerprint != fingerprints.end(); ++fingerprint) {
		bool	found = false;
		for (std::vector<std::string>::const_iterator version_dir(version_dirs.begin()); version_dir != version_dirs.end(); ++version_dir) {
			const std::string	gpg_file(key_path + "/" + *version_dir + "/" + *fingerprint + ".gpg");
			if (access(gpg_file.c_str(), F_OK) == 0) {
				found = true;
				removed_files.push_back(gpg_file);
			}
		}

		if (!found) {
			std::clog << "Error: GPG user " << *fingerprint << " not found";
			if (key_name) {
				std::clog << " in key '" << key_name << "'";
			}
			std::clog << std::endl;
			return 1;
		}
	}

	// Stage removals with git rm
	{
		std::vector<std::string>	command;
		command.push_back("git");
		command.push_back("rm");
		command.push_back("--quiet");
		command.push_back("--");
		command.insert(command.end(), removed_files.begin(), removed_files.end());
		if (!successful_exit(exec_command(command))) {
			std::clog << "Error: 'git rm' failed" << std::endl;
			return 1;
		}
	}

	// Commit unless --no-commit
	if (!no_commit) {
		std::ostringstream	commit_message_builder;
		commit_message_builder << "Remove " << fingerprints.size() << " git-crypt collaborator" << (fingerprints.size() != 1 ? "s" : "") << "\n\nRemoved collaborators:\n\n";
		for (std::vector<std::string>::const_iterator fp(fingerprints.begin()); fp != fingerprints.end(); ++fp) {
			commit_message_builder << "    " << *fp << '\n';
			const std::string uid(gpg_get_uid(*fp));
			if (!uid.empty()) {
				commit_message_builder << "        " << uid << '\n';
			}
		}

		std::vector<std::string>	command;
		command.push_back("git");
		command.push_back("commit");
		command.push_back("-m");
		command.push_back(commit_message_builder.str());
		command.push_back("--");
		command.insert(command.end(), removed_files.begin(), removed_files.end());

		if (!successful_exit(exec_command(command))) {
			std::clog << "Error: 'git commit' failed" << std::endl;
			return 1;
		}
	}

	return 0;
}

void help_ls_gpg_users (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt ls-gpg-users [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    -k, --key-name KEYNAME      List users for given key, instead of all keys" << std::endl;
	out << std::endl;
}
int ls_gpg_users (int argc, const char** argv)
{
	const char*		key_name = 0;
	Options_list		options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));

	int			argi = parse_options(options, argc, argv);

	if (argc - argi != 0) {
		std::clog << "Error: git-crypt ls-gpg-users takes no arguments" << std::endl;
		help_ls_gpg_users(std::clog);
		return 2;
	}

	if (key_name) {
		validate_key_name_or_throw(key_name);
	}

	const std::string		repo_keys_path(get_repo_keys_path());

	if (access(repo_keys_path.c_str(), F_OK) != 0) {
		std::clog << "Error: no keys found - has git-crypt been set up in this repository?" << std::endl;
		return 1;
	}

	// Get list of key names (directory entries under keys/)
	std::vector<std::string>	key_names(get_directory_contents(repo_keys_path.c_str()));

	for (std::vector<std::string>::const_iterator kn(key_names.begin()); kn != key_names.end(); ++kn) {
		// If filtering by key name, skip non-matching entries
		if (key_name) {
			const std::string	target(key_name);
			if (*kn != target) {
				continue;
			}
		} else if (*kn != "default" && !validate_key_name(kn->c_str())) {
			continue;
		}

		const std::string	key_dir(repo_keys_path + "/" + *kn);

		// Get version subdirectories
		std::vector<std::string>	version_dirs(get_directory_contents(key_dir.c_str()));

		// Collect unique fingerprints across all versions
		std::vector<std::string>	unique_fingerprints;
		for (std::vector<std::string>::const_iterator vd(version_dirs.begin()); vd != version_dirs.end(); ++vd) {
			const std::string	version_path(key_dir + "/" + *vd);
			std::vector<std::string>	entries;
			try {
				entries = get_directory_contents(version_path.c_str());
			} catch (const System_error&) {
				continue;
			}
			for (std::vector<std::string>::const_iterator entry(entries.begin()); entry != entries.end(); ++entry) {
				// Only process .gpg files
				if (entry->size() > 4 && entry->substr(entry->size() - 4) == ".gpg") {
					const std::string	fingerprint(entry->substr(0, entry->size() - 4));
					// Check if already collected
					bool	already_listed = false;
					for (std::vector<std::string>::const_iterator fp(unique_fingerprints.begin()); fp != unique_fingerprints.end(); ++fp) {
						if (*fp == fingerprint) {
							already_listed = true;
							break;
						}
					}
					if (!already_listed) {
						unique_fingerprints.push_back(fingerprint);
					}
				}
			}
		}

		if (!unique_fingerprints.empty()) {
			std::cout << (*kn == "default" ? "default" : kn->c_str()) << ":" << std::endl;
			for (std::vector<std::string>::const_iterator fp(unique_fingerprints.begin()); fp != unique_fingerprints.end(); ++fp) {
				std::cout << "  0x" << *fp;
				const std::string	uid(gpg_get_uid(*fp));
				if (!uid.empty()) {
					std::cout << " " << uid;
				}
				std::cout << std::endl;
			}
		}
	}

	return 0;
}

void help_export_key (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt export-key [OPTIONS] FILENAME" << std::endl;
	out << std::endl;
	out << "    -k, --key-name KEYNAME      Export the given key, instead of the default" << std::endl;
	out << "    --version N                 Export only the specified key version" << std::endl;
	out << std::endl;
	out << "When FILENAME is -, export to standard out." << std::endl;
}
int export_key (int argc, const char** argv)
{
	const char*		key_name = 0;
	const char*		version_str = 0;
	Options_list		options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("--version", &version_str));

	int			argi = parse_options(options, argc, argv);

	if (argc - argi != 1) {
		std::clog << "Error: no filename specified" << std::endl;
		help_export_key(std::clog);
		return 2;
	}

	Key_file		key_file;
	load_key(key_file, key_name);

	// If a specific version was requested, create a key file with only that version
	if (version_str) {
		char*		end = 0;
		unsigned long	ver = std::strtoul(version_str, &end, 10);
		if (end == version_str || *end != '\0') {
			std::clog << "Error: invalid version number: " << version_str << std::endl;
			return 2;
		}
		uint32_t		version = static_cast<uint32_t>(ver);
		const Key_file::Entry*	entry = key_file.get(version);
		if (!entry) {
			std::clog << "Error: key version " << version << " not found" << std::endl;
			return 1;
		}
		Key_file	filtered_key_file;
		filtered_key_file.set_key_name(key_file.get_key_name());
		filtered_key_file.add(*entry);
		key_file = filtered_key_file;
	}

	const char*		out_file_name = argv[argi];

	if (std::strcmp(out_file_name, "-") == 0) {
		key_file.store(std::cout);
	} else {
		if (!key_file.store_to_file(out_file_name)) {
			std::clog << "Error: " << out_file_name << ": unable to write key file" << std::endl;
			return 1;
		}
	}

	return 0;
}

void help_keygen (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt keygen FILENAME" << std::endl;
	out << std::endl;
	out << "When FILENAME is -, write to standard out." << std::endl;
}
int keygen (int argc, const char** argv)
{
	if (argc != 1) {
		std::clog << "Error: no filename specified" << std::endl;
		help_keygen(std::clog);
		return 2;
	}

	const char*		key_file_name = argv[0];

	if (std::strcmp(key_file_name, "-") != 0 && access(key_file_name, F_OK) == 0) {
		std::clog << key_file_name << ": File already exists" << std::endl;
		return 1;
	}

	std::clog << "Generating key..." << std::endl;
	Key_file		key_file;
	key_file.generate();

	if (std::strcmp(key_file_name, "-") == 0) {
		key_file.store(std::cout);
	} else {
		if (!key_file.store_to_file(key_file_name)) {
			std::clog << "Error: " << key_file_name << ": unable to write key file" << std::endl;
			return 1;
		}
	}
	return 0;
}

void help_migrate_key (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt migrate-key OLDFILENAME NEWFILENAME" << std::endl;
	out << std::endl;
	out << "Use - to read from standard in/write to standard out." << std::endl;
}
int migrate_key (int argc, const char** argv)
{
	if (argc != 2) {
		std::clog << "Error: filenames not specified" << std::endl;
		help_migrate_key(std::clog);
		return 2;
	}

	const char*		key_file_name = argv[0];
	const char*		new_key_file_name = argv[1];
	Key_file		key_file;

	try {
		if (std::strcmp(key_file_name, "-") == 0) {
			key_file.load_legacy(std::cin);
		} else {
			std::ifstream	in(key_file_name, std::fstream::binary);
			if (!in) {
				std::clog << "Error: " << key_file_name << ": unable to open for reading" << std::endl;
				return 1;
			}
			key_file.load_legacy(in);
		}

		if (std::strcmp(new_key_file_name, "-") == 0) {
			key_file.store(std::cout);
		} else {
			if (!key_file.store_to_file(new_key_file_name)) {
				std::clog << "Error: " << new_key_file_name << ": unable to write key file" << std::endl;
				return 1;
			}
		}
	} catch (Key_file::Malformed) {
		std::clog << "Error: " << key_file_name << ": not a valid legacy git-crypt key file" << std::endl;
		return 1;
	}

	return 0;
}

void help_refresh (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt refresh [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    -a, --all                Refresh all keys, instead of just the default" << std::endl;
	out << "    -k, --key-name KEYNAME   Refresh the given key, instead of the default" << std::endl;
	out << std::endl;
}
int refresh (int argc, const char** argv)
{
	const char*	key_name = 0;
	bool		all_keys = false;
	Options_list	options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("-a", &all_keys));
	options.push_back(Option_def("--all", &all_keys));

	int		argi = parse_options(options, argc, argv);

	if (argc - argi != 0) {
		std::clog << "Error: git-crypt refresh takes no arguments" << std::endl;
		help_refresh(std::clog);
		return 2;
	}

	if (all_keys && key_name) {
		std::clog << "Error: -k and --all options are mutually exclusive" << std::endl;
		return 2;
	}

	if (key_name) {
		validate_key_name_or_throw(key_name);
	}

	// Collect encrypted files
	std::vector<std::string>	encrypted_files;
	if (all_keys) {
		std::vector<std::string>	dirents(get_directory_contents(get_internal_keys_path().c_str()));
		for (std::vector<std::string>::const_iterator dirent(dirents.begin()); dirent != dirents.end(); ++dirent) {
			const char*	this_key_name = (*dirent == "default" ? 0 : dirent->c_str());
			get_encrypted_files(encrypted_files, this_key_name);
		}
	} else {
		get_encrypted_files(encrypted_files, key_name);
	}

	if (encrypted_files.empty()) {
		std::clog << "No encrypted files found." << std::endl;
		return 0;
	}

	// Touch every file so git checkout will re-apply the smudge filter
	for (std::vector<std::string>::const_iterator file(encrypted_files.begin()); file != encrypted_files.end(); ++file) {
		touch_file(*file);
	}

	if (!git_checkout(encrypted_files)) {
		std::clog << "Error: 'git checkout' failed" << std::endl;
		return 1;
	}

	std::clog << encrypted_files.size() << " file" << (encrypted_files.size() != 1 ? "s" : "") << " refreshed." << std::endl;
	return 0;
}

void help_rotate_key (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt rotate-key [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    -k, --key-name KEYNAME      Rotate the given key, instead of the default" << std::endl;
	out << "    -n, --no-commit             Don't automatically commit" << std::endl;
	out << std::endl;
}
int rotate_key (int argc, const char** argv)
{
	const char*	key_name = 0;
	bool		no_commit = false;
	Options_list	options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("-n", &no_commit));
	options.push_back(Option_def("--no-commit", &no_commit));

	int		argi = parse_options(options, argc, argv);

	if (argc - argi != 0) {
		std::clog << "Error: git-crypt rotate-key takes no arguments" << std::endl;
		help_rotate_key(std::clog);
		return 2;
	}

	if (key_name) {
		validate_key_name_or_throw(key_name);
	}

	// 1. Load the existing key file
	Key_file		key_file;
	load_key(key_file, key_name);

	const Key_file::Entry*	old_latest = key_file.get_latest();
	if (!old_latest) {
		std::clog << "Error: key file is empty";
		if (key_name) {
			std::clog << " (key '" << key_name << "')";
		}
		std::clog << std::endl;
		return 1;
	}

	uint32_t		old_version = old_latest->version;

	// 2. Generate a new key version
	key_file.generate();

	const Key_file::Entry*	new_entry = key_file.get_latest();
	if (!new_entry || new_entry->version <= old_version) {
		std::clog << "Error: failed to generate new key version" << std::endl;
		return 1;
	}

	std::clog << "Rotating key";
	if (key_name) {
		std::clog << " '" << key_name << "'";
	}
	std::clog << ": version " << old_version << " -> " << new_entry->version << std::endl;

	// 3. Save the updated internal key file (now contains old + new versions)
	std::string		internal_key_path(get_internal_key_path(key_name));
	if (!key_file.store_to_file(internal_key_path.c_str())) {
		std::clog << "Error: " << internal_key_path << ": unable to write key file" << std::endl;
		return 1;
	}

	// 4. Re-encrypt all files for this key by staging them (clean filter uses new latest)
	std::vector<std::string>	encrypted_files;
	get_encrypted_files(encrypted_files, key_name);

	if (!encrypted_files.empty()) {
		std::clog << "Re-encrypting " << encrypted_files.size() << " file"
			  << (encrypted_files.size() != 1 ? "s" : "") << " with new key..." << std::endl;

		std::vector<std::string>	command;
		command.push_back("git");
		command.push_back("add");
		command.push_back("--");
		command.insert(command.end(), encrypted_files.begin(), encrypted_files.end());
		if (!successful_exit(exec_command(command))) {
			std::clog << "Error: 'git add' failed while re-encrypting files" << std::endl;
			return 1;
		}
	}

	// 5. Re-wrap the new key version for all existing GPG collaborators
	const std::string		repo_keys_path(get_repo_keys_path());
	const std::string		key_dir(repo_keys_path + "/" + (key_name ? key_name : "default"));
	std::vector<std::string>	new_gpg_files;

	if (access(key_dir.c_str(), F_OK) == 0) {
		// Collect unique GPG fingerprints from all version directories
		std::vector<std::string>	version_dirs(get_directory_contents(key_dir.c_str()));
		std::vector<std::pair<std::string, bool> >	collab_keys;

		for (std::vector<std::string>::const_iterator vd(version_dirs.begin()); vd != version_dirs.end(); ++vd) {
			const std::string	version_path(key_dir + "/" + *vd);
			std::vector<std::string>	entries;
			try {
				entries = get_directory_contents(version_path.c_str());
			} catch (const System_error&) {
				continue;
			}
			for (std::vector<std::string>::const_iterator entry(entries.begin()); entry != entries.end(); ++entry) {
				if (entry->size() > 4 && entry->substr(entry->size() - 4) == ".gpg") {
					const std::string	fingerprint(entry->substr(0, entry->size() - 4));
					bool	already_listed = false;
					for (std::vector<std::pair<std::string, bool> >::const_iterator ck(collab_keys.begin()); ck != collab_keys.end(); ++ck) {
						if (ck->first == fingerprint) {
							already_listed = true;
							break;
						}
					}
					if (!already_listed) {
						collab_keys.push_back(std::make_pair(fingerprint, true));
					}
				}
			}
		}

		if (!collab_keys.empty()) {
			std::clog << "Re-wrapping key for " << collab_keys.size()
				  << " GPG collaborator" << (collab_keys.size() != 1 ? "s" : "") << "..." << std::endl;

			encrypt_repo_key(key_name, *new_entry, collab_keys, repo_keys_path, &new_gpg_files);
		}
	}

	// 6. Stage and commit
	std::vector<std::string>	all_new_files;
	all_new_files.insert(all_new_files.end(), new_gpg_files.begin(), new_gpg_files.end());

	if (!all_new_files.empty()) {
		std::vector<std::string>	command;
		command.push_back("git");
		command.push_back("add");
		command.push_back("--");
		command.insert(command.end(), all_new_files.begin(), all_new_files.end());
		if (!successful_exit(exec_command(command))) {
			std::clog << "Error: 'git add' failed while staging GPG-wrapped keys" << std::endl;
			return 1;
		}
	}

	if (!no_commit && (!encrypted_files.empty() || !all_new_files.empty())) {
		std::ostringstream	commit_message_builder;
		commit_message_builder << "Rotate git-crypt key";
		if (key_name) {
			commit_message_builder << " '" << key_name << "'";
		}
		commit_message_builder << " to version " << new_entry->version;
		commit_message_builder << "\n\nRe-encrypted " << encrypted_files.size() << " file"
				       << (encrypted_files.size() != 1 ? "s" : "") << ".";
		if (!new_gpg_files.empty()) {
			commit_message_builder << "\nRe-wrapped key for " << new_gpg_files.size()
					       << " GPG collaborator file" << (new_gpg_files.size() != 1 ? "s" : "") << ".";
		}

		std::vector<std::string>	command;
		command.push_back("git");
		command.push_back("commit");
		command.push_back("-m");
		command.push_back(commit_message_builder.str());
		if (!successful_exit(exec_command(command))) {
			std::clog << "Error: 'git commit' failed" << std::endl;
			return 1;
		}
	}

	std::clog << "Key rotation complete." << std::endl;
	return 0;
}

void help_status (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt status [OPTIONS] [FILE ...]" << std::endl;
	//out << "   or: git-crypt status -r [OPTIONS]" << std::endl;
	//out << "   or: git-crypt status -f" << std::endl;
	out << std::endl;
	out << "    -e             Show encrypted files only" << std::endl;
	out << "    -u             Show unencrypted files only" << std::endl;
	//out << "    -r             Show repository status only" << std::endl;
	out << "    -f, --fix      Fix problems with the repository" << std::endl;
	out << "    -z, -m         Machine-parseable output (NUL-terminated TSV)" << std::endl;
	out << std::endl;
}
int status (int argc, const char** argv)
{
	// Usage:
	//  git-crypt status -r [-z]			Show repo status
	//  git-crypt status [-e | -u] [-z] [FILE ...]	Show encrypted status of files
	//  git-crypt status -f				Fix unencrypted blobs

	bool		repo_status_only = false;	// -r show repo status only
	bool		show_encrypted_only = false;	// -e show encrypted files only
	bool		show_unencrypted_only = false;	// -u show unencrypted files only
	bool		fix_problems = false;		// -f fix problems
	bool		machine_output = false;		// -z machine-parseable output

	Options_list	options;
	options.push_back(Option_def("-r", &repo_status_only));
	options.push_back(Option_def("-e", &show_encrypted_only));
	options.push_back(Option_def("-u", &show_unencrypted_only));
	options.push_back(Option_def("-f", &fix_problems));
	options.push_back(Option_def("--fix", &fix_problems));
	options.push_back(Option_def("-z", &machine_output));
	options.push_back(Option_def("-m", &machine_output));
	options.push_back(Option_def("--machine", &machine_output));

	int		argi = parse_options(options, argc, argv);

	if (repo_status_only) {
		if (show_encrypted_only || show_unencrypted_only) {
			std::clog << "Error: -e and -u options cannot be used with -r" << std::endl;
			return 2;
		}
		if (fix_problems) {
			std::clog << "Error: -f option cannot be used with -r" << std::endl;
			return 2;
		}
		if (argc - argi != 0) {
			std::clog << "Error: filenames cannot be specified when -r is used" << std::endl;
			return 2;
		}
	}

	if (show_encrypted_only && show_unencrypted_only) {
		std::clog << "Error: -e and -u options are mutually exclusive" << std::endl;
		return 2;
	}

	if (fix_problems && (show_encrypted_only || show_unencrypted_only)) {
		std::clog << "Error: -e and -u options cannot be used with -f" << std::endl;
		return 2;
	}

	if (machine_output && fix_problems) {
		std::clog << "Error: -z/-m option cannot be used with -f" << std::endl;
		return 2;
	}

	if (argc - argi == 0) {
		// TODO: check repo status:
		//	is it set up for git-crypt?
		//	which keys are unlocked?
		//	--> check for filter config (see configure_git_filters()) and corresponding internal key

		if (repo_status_only) {
			return 0;
		}
	}

	// git ls-files -cotsz --exclude-standard ...
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("ls-files");
	command.push_back("-cotsz");
	command.push_back("--exclude-standard");
	command.push_back("--");
	if (argc - argi == 0) {
		const std::string	path_to_top(get_path_to_top());
		if (!path_to_top.empty()) {
			command.push_back(path_to_top);
		}
	} else {
		for (int i = argi; i < argc; ++i) {
			command.push_back(argv[i]);
		}
	}

	std::stringstream		output;
	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git ls-files' failed - is this a Git repository?");
	}

	// Output looks like (w/o newlines):
	// ? .gitignore\0
	// H 100644 06ec22e5ed0de9280731ef000a10f9c3fbc26338 0     afile\0

	std::vector<std::string>	files;
	bool				attribute_errors = false;
	bool				unencrypted_blob_errors = false;
	bool				tamper_warnings = false;
	unsigned int			nbr_of_fixed_blobs = 0;
	unsigned int			nbr_of_fix_errors = 0;

	while (output.peek() != -1) {
		std::string		tag;
		std::string		object_id;
		std::string		filename;
		output >> tag;
		if (tag != "?") {
			std::string	mode;
			std::string	stage;
			output >> mode >> object_id >> stage;
			if (!is_git_file_mode(mode)) {
				continue;
			}
		}
		output >> std::ws;
		std::getline(output, filename, '\0');

		// TODO: get file attributes en masse for efficiency... unfortunately this requires machine-parseable output from git check-attr to be workable, and this is only supported in Git 1.8.5 and above (released 27 Nov 2013)
		const std::pair<std::string, std::string> file_attrs(get_file_attributes(filename));

		if (file_attrs.first == "git-crypt" || std::strncmp(file_attrs.first.c_str(), "git-crypt-", 10) == 0) {
			// File is encrypted
			const bool	blob_is_unencrypted = !object_id.empty() && !check_if_blob_is_encrypted(object_id);
			const bool	filter_ok = (file_attrs.second == file_attrs.first);

			// Determine the key name from the filter attribute
			std::string	key_name_str;
			if (file_attrs.first == "git-crypt") {
				key_name_str = "default";
			} else {
				// "git-crypt-<name>" -> "<name>"
				key_name_str = file_attrs.first.substr(10);
			}

			if (fix_problems && blob_is_unencrypted) {
				if (access(filename.c_str(), F_OK) != 0) {
					std::clog << "Error: " << filename << ": cannot stage encrypted version because not present in working tree - please 'git rm' or 'git checkout' it" << std::endl;
					++nbr_of_fix_errors;
				} else {
					touch_file(filename);
					std::vector<std::string>	git_add_command;
					git_add_command.push_back("git");
					git_add_command.push_back("add");
					git_add_command.push_back("--");
					git_add_command.push_back(filename);
					if (!successful_exit(exec_command(git_add_command))) {
						throw Error("'git-add' failed");
					}
					if (check_if_file_is_encrypted(filename)) {
						std::cout << filename << ": staged encrypted version" << std::endl;
						++nbr_of_fixed_blobs;
					} else {
						std::clog << "Error: " << filename << ": still unencrypted even after staging" << std::endl;
						++nbr_of_fix_errors;
					}
				}
			} else if (!fix_problems && !show_unencrypted_only) {
				if (machine_output) {
					// NUL-terminated TSV: filename \t encrypted \t filter_ok \t key_name \0
					std::cout << filename << '\t' << "encrypted" << '\t' << (filter_ok ? "true" : "false") << '\t' << key_name_str << '\0';
				} else {
					std::cout << "    encrypted: " << filename;
					if (!filter_ok) {
						// but diff filter is not properly set
						std::cout << " *** WARNING: diff=" << file_attrs.first << " attribute not set ***";
						attribute_errors = true;
					}
					if (blob_is_unencrypted) {
						// File not actually encrypted
						std::cout << " *** WARNING: staged/committed version is NOT ENCRYPTED! ***";
						unencrypted_blob_errors = true;
					}
					std::cout << std::endl;
				}
			}
		} else {
			// File not encrypted (per .gitattributes)
			// Check for .gitattributes tampering: blob is encrypted but filter attribute is missing
			const bool	blob_is_encrypted = !object_id.empty() && check_if_blob_is_encrypted(object_id);
			if (blob_is_encrypted) {
				// Blob is encrypted but filter attribute is missing — possible .gitattributes tampering
				if (!fix_problems) {
					if (machine_output) {
						std::cout << filename << '\t' << "tampered" << '\t' << "false" << '\t' << "" << '\0';
					} else {
						std::cout << "*** TAMPERED: " << filename << " *** (encrypted blob but filter attribute removed from .gitattributes)" << std::endl;
					}
					tamper_warnings = true;
				}
			} else if (!fix_problems && !show_encrypted_only) {
				if (machine_output) {
					// NUL-terminated TSV: filename \t not_encrypted \t \t \0
					std::cout << filename << '\t' << "not_encrypted" << '\t' << "" << '\t' << "" << '\0';
				} else {
					std::cout << "not encrypted: " << filename << std::endl;
				}
			}
		}
	}

	int				exit_status = 0;

	if (!machine_output && tamper_warnings) {
		std::cout << std::endl;
		std::cout << "WARNING: .gitattributes may have been tampered with!" << std::endl;
		std::cout << "One or more files have encrypted blobs in the repository but their" << std::endl;
		std::cout << "git-crypt filter attribute has been removed from .gitattributes." << std::endl;
		std::cout << "This means future modifications to these files will be committed in PLAINTEXT." << std::endl;
		std::cout << "Please verify .gitattributes has not been maliciously modified and restore" << std::endl;
		std::cout << "the correct filter=git-crypt diff=git-crypt attributes for affected files." << std::endl;
		exit_status = 1;
	}
	if (!machine_output && attribute_errors) {
		std::cout << std::endl;
		std::cout << "Warning: one or more files has a git-crypt filter attribute but not a" << std::endl;
		std::cout << "corresponding git-crypt diff attribute.  For proper 'git diff' operation" << std::endl;
		std::cout << "you should fix the .gitattributes file to specify the correct diff attribute." << std::endl;
		std::cout << "Consult the git-crypt documentation for help." << std::endl;
		exit_status = 1;
	}
	if (!machine_output && unencrypted_blob_errors) {
		std::cout << std::endl;
		std::cout << "Warning: one or more files is marked for encryption via .gitattributes but" << std::endl;
		std::cout << "was staged and/or committed before the .gitattributes file was in effect." << std::endl;
		std::cout << "Run 'git-crypt status' with the '-f' option to stage an encrypted version." << std::endl;
		exit_status = 1;
	}
	if (nbr_of_fixed_blobs) {
		std::cout << "Staged " << nbr_of_fixed_blobs << " encrypted file" << (nbr_of_fixed_blobs != 1 ? "s" : "") << "." << std::endl;
		std::cout << "Warning: if these files were previously committed, unencrypted versions still exist in the repository's history." << std::endl;
	}
	if (nbr_of_fix_errors) {
		std::cout << "Unable to stage " << nbr_of_fix_errors << " file" << (nbr_of_fix_errors != 1 ? "s" : "") << "." << std::endl;
		exit_status = 1;
	}

	return exit_status;
}

