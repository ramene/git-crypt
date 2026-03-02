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
#include "age.hpp"
#include "shamir.hpp"
#include "sops.hpp"
#include "audit.hpp"
#include "wallet.hpp"
#include "parse_options.hpp"
#include "coprocess.hpp"
#include <unistd.h>
#include <sys/stat.h>
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
#include <set>

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

// Try to decrypt a repo key using age (try all .age files in the version directory)
static bool decrypt_repo_key_age (Key_file& key_file, const char* key_name, uint32_t key_version, const std::string& keys_path)
{
	std::ostringstream	dir_builder;
	dir_builder << keys_path << '/' << (key_name ? key_name : "default") << '/' << key_version;
	std::string		version_dir(dir_builder.str());

	if (access(version_dir.c_str(), F_OK) != 0) {
		return false;
	}

	std::vector<std::string>	dirents(get_directory_contents(version_dir.c_str()));
	for (std::vector<std::string>::const_iterator entry(dirents.begin()); entry != dirents.end(); ++entry) {
		// Look for .age files
		if (entry->size() > 4 && entry->substr(entry->size() - 4) == ".age") {
			std::string		path(version_dir + "/" + *entry);
			std::stringstream	decrypted_contents;
			if (age_decrypt_from_file(path, decrypted_contents)) {
				Key_file		this_version_key_file;
				this_version_key_file.load(decrypted_contents);
				const Key_file::Entry*	this_version_entry = this_version_key_file.get(key_version);
				if (!this_version_entry) {
					throw Error("Age-encrypted keyfile is malformed because it does not contain expected key version");
				}
				if (!same_key_name(key_name, this_version_key_file.get_key_name())) {
					throw Error("Age-encrypted keyfile is malformed because it does not contain expected key name");
				}
				key_file.set_key_name(key_name);
				key_file.add(*this_version_entry);
				return true;
			}
		}
	}

	return false;
}

// Encrypt a repo key for a list of age recipients
static void encrypt_repo_key_age (const char* key_name, const Key_file::Entry& key, const std::vector<std::string>& recipients, const std::string& keys_path, std::vector<std::string>* new_files)
{
	std::string	key_file_data;
	{
		Key_file this_version_key_file;
		this_version_key_file.set_key_name(key_name);
		this_version_key_file.add(key);
		key_file_data = this_version_key_file.store_to_string();
	}

	for (std::vector<std::string>::const_iterator recipient(recipients.begin()); recipient != recipients.end(); ++recipient) {
		std::string		hash(age_recipient_hash(*recipient));
		std::ostringstream	path_builder;
		path_builder << keys_path << '/' << (key_name ? key_name : "default") << '/' << key.version << '/' << hash << ".age";
		std::string		path(path_builder.str());

		if (access(path.c_str(), F_OK) == 0) {
			continue;
		}

		mkdir_parent(path);
		age_encrypt_to_file(path, *recipient, key_file_data.data(), key_file_data.size());
		new_files->push_back(path);
	}
}

// Try to decrypt a repo key using a wallet-derived identity
// Looks for .age files in the wallet/ subdirectory of each version
static bool decrypt_repo_key_wallet (Key_file& key_file, const char* key_name, uint32_t key_version, const std::string& keys_path, const std::string& wallet_identity_hex)
{
	std::ostringstream	dir_builder;
	dir_builder << keys_path << '/' << (key_name ? key_name : "default") << '/' << key_version << "/wallet";
	std::string		wallet_dir(dir_builder.str());

	if (access(wallet_dir.c_str(), F_OK) != 0) {
		return false;
	}

	std::vector<std::string>	dirents(get_directory_contents(wallet_dir.c_str()));
	for (std::vector<std::string>::const_iterator entry(dirents.begin()); entry != dirents.end(); ++entry) {
		if (entry->size() > 4 && entry->substr(entry->size() - 4) == ".age") {
			std::string		path(wallet_dir + "/" + *entry);
			std::stringstream	decrypted_contents;
			if (wallet_decrypt_from_file(path, wallet_identity_hex, decrypted_contents)) {
				Key_file		this_version_key_file;
				this_version_key_file.load(decrypted_contents);
				const Key_file::Entry*	this_version_entry = this_version_key_file.get(key_version);
				if (!this_version_entry) {
					throw Error("Wallet-encrypted keyfile is malformed because it does not contain expected key version");
				}
				if (!same_key_name(key_name, this_version_key_file.get_key_name())) {
					throw Error("Wallet-encrypted keyfile is malformed because it does not contain expected key name");
				}
				key_file.set_key_name(key_name);
				key_file.add(*this_version_entry);
				return true;
			}
		}
	}

	return false;
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
	out << "    --sops                      Also generate .sops.yaml for structured files" << std::endl;
	out << std::endl;
}

int init (int argc, const char** argv)
{
	const char*	key_name = 0;
	bool		force = false;
	bool		setup_sops = false;
	Options_list	options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("-f", &force));
	options.push_back(Option_def("--force", &force));
	options.push_back(Option_def("--sops", &setup_sops));

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

	// 3. Optionally set up SOPS integration
	if (setup_sops) {
		std::vector<std::string>	recipients = sops_collect_age_recipients(key_name);
		std::vector<std::string>	patterns;
		patterns.push_back("secrets\\.ya?ml$");
		patterns.push_back("secrets\\.json$");
		patterns.push_back("\\.env(\\..+)?$");
		if (sops_generate_config(".sops.yaml", recipients, patterns)) {
			std::clog << "SOPS config written to .sops.yaml" << std::endl;
		} else {
			std::clog << "Warning: unable to write .sops.yaml" << std::endl;
		}
	}

	return 0;
}

void help_unlock (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt unlock [OPTIONS]" << std::endl;
	out << "   or: git-crypt unlock [OPTIONS] KEY_FILE ..." << std::endl;
	out << "   or: git-crypt unlock --shares FILE1 FILE2 ..." << std::endl;
	out << "   or: git-crypt unlock --wallet ADDRESS" << std::endl;
	out << std::endl;
	out << "    -k, --key-name KEYNAME   Unlock only the given key, instead of all keys" << std::endl;
	out << "    --shares FILE ...        Reconstruct key from Shamir share files" << std::endl;
	out << "    --wallet ADDRESS         Unlock using wallet-derived identity" << std::endl;
	out << std::endl;
}
int unlock (int argc, const char** argv)
{
	const char*	key_name_filter = 0;
	bool		use_shares = false;
	const char*	wallet_address = 0;
	Options_list	options;
	options.push_back(Option_def("-k", &key_name_filter));
	options.push_back(Option_def("--key-name", &key_name_filter));
	options.push_back(Option_def("--shares", &use_shares));
	options.push_back(Option_def("--wallet", &wallet_address));

	int		argi = parse_options(options, argc, argv);

	if (key_name_filter) {
		validate_key_name_or_throw(key_name_filter);
	}

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
	if (use_shares) {
		// Reconstruct key from Shamir share files
		if (argc - argi < 2) {
			std::clog << "Error: --shares requires at least 2 share files" << std::endl;
			help_unlock(std::clog);
			return 2;
		}

		std::vector<Shamir_share>	shares;
		for (int i = argi; i < argc; ++i) {
			Shamir_share	share;
			if (!share.load_from_file(argv[i])) {
				std::clog << "Error: " << argv[i] << ": unable to read share file" << std::endl;
				return 1;
			}
			shares.push_back(share);
		}

		std::cout << "Combining " << shares.size() << " shares (threshold: "
			  << static_cast<int>(shares[0].threshold) << ")..." << std::endl;

		std::string	key_data = shamir_combine(shares);

		Key_file	key_file;
		try {
			std::istringstream	key_stream(key_data);
			key_file.load(key_stream);
		} catch (Key_file::Incompatible) {
			std::clog << "Error: reconstructed key is in an incompatible format" << std::endl;
			return 1;
		} catch (Key_file::Malformed) {
			std::clog << "Error: reconstructed key is malformed (wrong shares?)" << std::endl;
			return 1;
		}

		// Securely clear key data
		explicit_memset(&key_data[0], 0, key_data.size());

		if (key_name_filter && !same_key_name(key_name_filter, key_file.get_key_name())) {
			std::clog << "Error: reconstructed key name does not match --key-name filter" << std::endl;
			return 1;
		}
		key_files.push_back(key_file);
	} else if (wallet_address) {
		// Unlock using wallet-derived identity
		if (!wallet_signer_is_available()) {
			std::clog << "Error: wallet signer tool not found." << std::endl;
			std::clog << "Install Foundry (https://getfoundry.sh) or configure: git config wallet.signer <path>" << std::endl;
			return 1;
		}
		if (!age_is_available()) {
			std::clog << "Error: 'age' command not found. Please install age." << std::endl;
			return 1;
		}

		std::string	challenge = wallet_challenge_message();
		std::clog << "Signing challenge with wallet " << wallet_address << "..." << std::endl;

		std::string	signature = wallet_sign_message(wallet_address, challenge);
		std::string	identity_hex = wallet_derive_age_identity(signature);

		std::string			repo_keys_path(get_repo_keys_path());

		if (key_name_filter) {
			std::string	key_dir_path(repo_keys_path + "/" + key_name_filter);
			uint32_t	key_version = get_latest_key_version(key_dir_path);
			Key_file	key_file;
			bool		decrypted = decrypt_repo_key_wallet(key_file, key_name_filter, key_version, repo_keys_path, identity_hex);
			if (!decrypted) {
				std::clog << "Error: wallet identity cannot decrypt key '" << key_name_filter << "'." << std::endl;
				return 1;
			}
			key_files.push_back(key_file);
		} else {
			std::vector<std::string>	dirents;
			if (access(repo_keys_path.c_str(), F_OK) == 0) {
				dirents = get_directory_contents(repo_keys_path.c_str());
			}
			for (std::vector<std::string>::const_iterator dirent(dirents.begin()); dirent != dirents.end(); ++dirent) {
				const char*	kn = 0;
				if (*dirent != "default") {
					if (!validate_key_name(dirent->c_str())) {
						continue;
					}
					kn = dirent->c_str();
				}
				std::string	key_dir_path(repo_keys_path + "/" + *dirent);
				uint32_t	key_version = get_latest_key_version(key_dir_path);
				Key_file	key_file;
				if (decrypt_repo_key_wallet(key_file, kn, key_version, repo_keys_path, identity_hex)) {
					key_files.push_back(key_file);
				}
			}
			if (key_files.empty()) {
				std::clog << "Error: wallet identity cannot decrypt any keys in this repository." << std::endl;
				return 1;
			}
		}

		explicit_memset(&identity_hex[0], 0, identity_hex.size());
	} else if (argc - argi > 0) {
		// Read from the symmetric key file(s)

		for (int i = argi; i < argc; ++i) {
			const char*	symmetric_key_file = argv[i];
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

			// If --key-name filter is set, skip keys that don't match
			if (key_name_filter && !same_key_name(key_name_filter, key_file.get_key_name())) {
				continue;
			}
			key_files.push_back(key_file);
		}
	} else {
		// Decrypt key from root of repo (try GPG first, then age)
		std::string			repo_keys_path(get_repo_keys_path());

		// Try to get GPG secret keys (may fail if GPG is not installed)
		std::vector<std::string>	gpg_secret_keys;
		bool				gpg_available = true;
		try {
			gpg_secret_keys = gpg_list_secret_keys();
		} catch (...) {
			gpg_available = false;
		}

		if (key_name_filter) {
			// Selective unlock: only decrypt the specified key
			std::string		key_dir_path(repo_keys_path + "/" + key_name_filter);
			uint32_t		key_version = get_latest_key_version(key_dir_path);

			Key_file	key_file;
			bool		decrypted = false;

			// Try GPG first
			if (gpg_available) {
				decrypted = decrypt_repo_key(key_file, key_name_filter, key_version, gpg_secret_keys, repo_keys_path);
			}
			// Fall back to age
			if (!decrypted) {
				decrypted = decrypt_repo_key_age(key_file, key_name_filter, key_version, repo_keys_path);
			}
			if (!decrypted) {
				std::clog << "Error: no GPG or age identity available to unlock key '" << key_name_filter << "'." << std::endl;
				std::clog << "To unlock with a shared symmetric key instead, specify the path to the symmetric key as an argument to 'git-crypt unlock'." << std::endl;
				return 1;
			}
			key_files.push_back(key_file);
		} else {
			// Unlock all keys: try GPG then age for each key directory
			// TODO: avoid decrypting repo keys which are already unlocked in the .git directory
			std::vector<std::string>	dirents;
			if (access(repo_keys_path.c_str(), F_OK) == 0) {
				dirents = get_directory_contents(repo_keys_path.c_str());
			}

			for (std::vector<std::string>::const_iterator dirent(dirents.begin()); dirent != dirents.end(); ++dirent) {
				const char*	key_name = 0;
				if (*dirent != "default") {
					if (!validate_key_name(dirent->c_str())) {
						continue;
					}
					key_name = dirent->c_str();
				}

				std::string	key_dir_path(repo_keys_path + "/" + *dirent);
				uint32_t	key_version = get_latest_key_version(key_dir_path);
				Key_file	key_file;
				bool		decrypted = false;

				// Try GPG first
				if (gpg_available) {
					decrypted = decrypt_repo_key(key_file, key_name, key_version, gpg_secret_keys, repo_keys_path);
				}
				// Fall back to age
				if (!decrypted) {
					decrypted = decrypt_repo_key_age(key_file, key_name, key_version, repo_keys_path);
				}
				if (decrypted) {
					key_files.push_back(key_file);
				}
			}

			if (key_files.empty()) {
				std::clog << "Error: no GPG or age identity available to unlock this repository." << std::endl;
				std::clog << "To unlock with a shared symmetric key instead, specify the path to the symmetric key as an argument to 'git-crypt unlock'." << std::endl;
				std::clog << "To see a list of GPG keys authorized to unlock this repository, run 'git-crypt ls-gpg-users'." << std::endl;
				return 1;
			}
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

	// 5. Audit log
	{
		std::string	id_type;
		std::string	identity = audit_get_identity(id_type);
		if (use_shares) {
			id_type = "shamir";
		}
		audit_log_operation("unlock", identity, id_type, key_name_filter, encrypted_files);
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

	// 4. Audit log
	{
		std::string	id_type;
		std::string	identity = audit_get_identity(id_type);
		audit_log_operation("lock", identity, id_type, key_name, encrypted_files);
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
	out << "    --retroactive               Grant access to all key versions, not just latest" << std::endl;
	out << std::endl;
}
int add_gpg_user (int argc, const char** argv)
{
	const char*		key_name = 0;
	bool			no_commit = false;
	bool			trusted = false;
	bool			retroactive = false;
	Options_list		options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("-n", &no_commit));
	options.push_back(Option_def("--no-commit", &no_commit));
	options.push_back(Option_def("--trusted", &trusted));
	options.push_back(Option_def("--retroactive", &retroactive));

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

	Key_file			key_file;
	load_key(key_file, key_name);
	const Key_file::Entry*		latest_key = key_file.get_latest();
	if (!latest_key) {
		std::clog << "Error: key file is empty";
		if (key_name) {
			std::clog << " (key '" << key_name << "')";
		}
		std::clog << std::endl;
		return 1;
	}

	const std::string		state_path(get_repo_state_path());
	std::vector<std::string>	new_files;

	if (retroactive) {
		// Grant access to all key versions (0 through latest)
		for (uint32_t v = 0; v <= latest_key->version; ++v) {
			const Key_file::Entry*	entry = key_file.get(v);
			if (entry) {
				encrypt_repo_key(key_name, *entry, collab_keys, get_repo_keys_path(state_path), &new_files);
			}
		}
	} else {
		// Default: only grant access to the latest key version
		encrypt_repo_key(key_name, *latest_key, collab_keys, get_repo_keys_path(state_path), &new_files);
	}

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
			if (retroactive) {
				commit_message_builder << " (retroactive: all key versions)";
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

void help_add_age_recipient (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt add-age-recipient [OPTIONS] AGE_RECIPIENT ..." << std::endl;
	out << "   or: git-crypt add-age-recipient [OPTIONS] --ssh SSH_KEY_FILE ..." << std::endl;
	out << "   or: git-crypt add-age-recipient [OPTIONS] --yubikey" << std::endl;
	out << std::endl;
	out << "    -k, --key-name KEYNAME      Add recipient to given key, instead of default" << std::endl;
	out << "    -n, --no-commit             Don't automatically commit" << std::endl;
	out << "    --ssh                       Read SSH public keys from files" << std::endl;
	out << "    --yubikey                   Use YubiKey PIV via age-plugin-yubikey" << std::endl;
	out << std::endl;
	out << "AGE_RECIPIENT is an age public key (age1...) or SSH public key string." << std::endl;
	out << "With --ssh, arguments are paths to SSH public key files." << std::endl;
	out << std::endl;
	out << "Configuration:" << std::endl;
	out << "    git config age.program PATH   Path to age binary (default: age)" << std::endl;
	out << "    git config age.identity PATH  Path to age identity file for unlock" << std::endl;
	out << "    AGE_IDENTITY env var          Alternative to age.identity config" << std::endl;
	out << std::endl;
}
int add_age_recipient (int argc, const char** argv)
{
	const char*		key_name = 0;
	bool			no_commit = false;
	bool			ssh_mode = false;
	bool			yubikey_mode = false;
	Options_list		options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("-n", &no_commit));
	options.push_back(Option_def("--no-commit", &no_commit));
	options.push_back(Option_def("--ssh", &ssh_mode));
	options.push_back(Option_def("--yubikey", &yubikey_mode));

	int			argi = parse_options(options, argc, argv);
	if (!yubikey_mode && argc - argi == 0) {
		std::clog << "Error: no age recipient specified" << std::endl;
		help_add_age_recipient(std::clog);
		return 2;
	}

	// Verify age is available
	if (!age_is_available()) {
		std::clog << "Error: 'age' command not found. Please install age (https://age-encryption.org)." << std::endl;
		std::clog << "Or set 'git config age.program' to the path of the age binary." << std::endl;
		return 1;
	}

	// Collect recipient strings
	std::vector<std::string>	recipients;
	if (yubikey_mode) {
		// Detect YubiKey identities via age-plugin-yubikey
		if (!age_yubikey_is_available()) {
			std::clog << "Error: 'age-plugin-yubikey' not found." << std::endl;
			std::clog << "Install it from https://github.com/str4d/age-plugin-yubikey" << std::endl;
			return 1;
		}
		recipients = age_yubikey_list_recipients();
		if (recipients.empty()) {
			std::clog << "Error: no YubiKey identities found." << std::endl;
			std::clog << "Insert a YubiKey and ensure age-plugin-yubikey can detect it." << std::endl;
			return 1;
		}
		std::clog << "Found " << recipients.size() << " YubiKey identity" << (recipients.size() != 1 ? "ies" : "") << ":" << std::endl;
		for (std::vector<std::string>::const_iterator r(recipients.begin()); r != recipients.end(); ++r) {
			std::clog << "  " << *r << std::endl;
		}
	} else if (ssh_mode) {
		// Read SSH public keys from files
		for (int i = argi; i < argc; ++i) {
			std::ifstream	key_file(argv[i]);
			if (!key_file) {
				std::clog << "Error: unable to read SSH key file: " << argv[i] << std::endl;
				return 1;
			}
			std::string	line;
			bool		found_key = false;
			while (std::getline(key_file, line)) {
				// Skip empty lines and comments
				if (line.empty() || line[0] == '#') {
					continue;
				}
				// SSH public key format: type base64data [comment]
				// age accepts: "ssh-ed25519 AAAA..." or "ssh-rsa AAAA..."
				if (line.compare(0, 4, "ssh-") == 0 ||
				    line.compare(0, 11, "ecdsa-sha2-") == 0) {
					// Strip trailing comment for cleanliness:
					// keep "type base64" portion only
					std::string::size_type	first_space = line.find(' ');
					if (first_space != std::string::npos) {
						std::string::size_type	second_space = line.find(' ', first_space + 1);
						if (second_space != std::string::npos) {
							line = line.substr(0, second_space);
						}
					}
					recipients.push_back(line);
					found_key = true;
				}
			}
			if (!found_key) {
				std::clog << "Error: no SSH public key found in: " << argv[i] << std::endl;
				return 1;
			}
		}
	} else {
		for (int i = argi; i < argc; ++i) {
			recipients.push_back(argv[i]);
		}
	}

	// Load the symmetric key
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

	encrypt_repo_key_age(key_name, *key, recipients, get_repo_keys_path(state_path), &new_files);

	// Ensure .gitattributes in the state directory prevents encryption and marks age files as binary
	const std::string		state_gitattributes_path(state_path + "/.gitattributes");
	if (access(state_gitattributes_path.c_str(), F_OK) != 0) {
		std::ofstream		state_gitattributes_file(state_gitattributes_path.c_str());
		state_gitattributes_file << "# Do not edit this file.  To specify the files to encrypt, create your own\n";
		state_gitattributes_file << "# .gitattributes file in the directory where your files are.\n";
		state_gitattributes_file << "* !filter !diff\n";
		state_gitattributes_file << "*.gpg binary\n";
		state_gitattributes_file << "*.age binary\n";
		state_gitattributes_file.close();
		if (!state_gitattributes_file) {
			std::clog << "Error: unable to write " << state_gitattributes_path << std::endl;
			return 1;
		}
		new_files.push_back(state_gitattributes_path);
	} else {
		// Check if *.age binary line exists, append if not
		std::ifstream		existing_attrs(state_gitattributes_path.c_str());
		std::string		content;
		bool			has_age_binary = false;
		std::string		line;
		while (std::getline(existing_attrs, line)) {
			content += line + "\n";
			if (line.find("*.age binary") != std::string::npos) {
				has_age_binary = true;
			}
		}
		existing_attrs.close();

		if (!has_age_binary) {
			std::ofstream	attrs_out(state_gitattributes_path.c_str(), std::ios::app);
			attrs_out << "*.age binary\n";
			attrs_out.close();
			if (!attrs_out) {
				std::clog << "Error: unable to update " << state_gitattributes_path << std::endl;
				return 1;
			}
			new_files.push_back(state_gitattributes_path);
		}
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
			commit_message_builder << "Add " << recipients.size() << " git-crypt age recipient" << (recipients.size() != 1 ? "s" : "");
			if (key_name) {
				commit_message_builder << " for key '" << key_name << "'";
			}
			commit_message_builder << "\n\nNew age recipients:\n\n";
			for (std::vector<std::string>::const_iterator r(recipients.begin()); r != recipients.end(); ++r) {
				commit_message_builder << "    " << *r << '\n';
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

void help_rm_age_recipient (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt rm-age-recipient [OPTIONS] AGE_RECIPIENT ..." << std::endl;
	out << std::endl;
	out << "    -k, --key-name KEYNAME      Remove recipient from given key, instead of default" << std::endl;
	out << "    -n, --no-commit             Don't automatically commit" << std::endl;
	out << std::endl;
}
int rm_age_recipient (int argc, const char** argv)
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
		std::clog << "Error: no age recipient specified" << std::endl;
		help_rm_age_recipient(std::clog);
		return 2;
	}

	if (key_name) {
		validate_key_name_or_throw(key_name);
	}

	// Compute the hash for each recipient argument (same hash used by add-age-recipient)
	std::vector<std::string>	recipient_hashes;
	std::vector<std::string>	recipient_labels;
	for (int i = argi; i < argc; ++i) {
		recipient_hashes.push_back(age_recipient_hash(argv[i]));
		recipient_labels.push_back(argv[i]);
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

	for (size_t h = 0; h < recipient_hashes.size(); ++h) {
		bool	found = false;
		for (std::vector<std::string>::const_iterator version_dir(version_dirs.begin()); version_dir != version_dirs.end(); ++version_dir) {
			const std::string	age_file(key_path + "/" + *version_dir + "/" + recipient_hashes[h] + ".age");
			if (access(age_file.c_str(), F_OK) == 0) {
				found = true;
				removed_files.push_back(age_file);
			}
		}

		if (!found) {
			std::clog << "Error: age recipient " << recipient_labels[h] << " not found";
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
		commit_message_builder << "Remove " << recipient_hashes.size() << " git-crypt age recipient" << (recipient_hashes.size() != 1 ? "s" : "");
		if (key_name) {
			commit_message_builder << " from key '" << key_name << "'";
		}
		commit_message_builder << "\n\nRemoved age recipients:\n\n";
		for (size_t i = 0; i < recipient_labels.size(); ++i) {
			commit_message_builder << "    " << recipient_labels[i] << '\n';
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

void help_add_wallet_recipient (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt add-wallet-recipient [OPTIONS] ADDRESS" << std::endl;
	out << std::endl;
	out << "    -k, --key-name KEYNAME      Add recipient to given key, instead of default" << std::endl;
	out << "    -n, --no-commit             Don't automatically commit" << std::endl;
	out << std::endl;
	out << "ADDRESS is an Ethereum wallet address (0x...)." << std::endl;
	out << "The user will be prompted to sign a challenge message with their wallet." << std::endl;
	out << "An age identity is derived from the signature and used to wrap the key." << std::endl;
	out << std::endl;
	out << "Configuration:" << std::endl;
	out << "    git config wallet.signer PATH   Path to wallet signer (default: cast)" << std::endl;
	out << "    git config age.program PATH     Path to age binary (default: age)" << std::endl;
	out << std::endl;
}
int add_wallet_recipient (int argc, const char** argv)
{
	const char*		key_name = 0;
	bool			no_commit = false;
	Options_list		options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("-n", &no_commit));
	options.push_back(Option_def("--no-commit", &no_commit));

	int			argi = parse_options(options, argc, argv);
	if (argc - argi != 1) {
		std::clog << "Error: exactly one wallet address required" << std::endl;
		help_add_wallet_recipient(std::clog);
		return 2;
	}

	const std::string	address(argv[argi]);

	// Validate address format (basic check for 0x + 40 hex chars)
	if (address.size() != 42 || address[0] != '0' || address[1] != 'x') {
		std::clog << "Error: invalid Ethereum address format. Expected 0x followed by 40 hex characters." << std::endl;
		return 1;
	}
	for (size_t i = 2; i < address.size(); ++i) {
		char c = address[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
			std::clog << "Error: invalid hex character in address: " << c << std::endl;
			return 1;
		}
	}

	// Check that wallet signer is available
	if (!wallet_signer_is_available()) {
		std::clog << "Error: wallet signer tool not found." << std::endl;
		std::clog << "Install Foundry (https://getfoundry.sh) for 'cast', or configure:" << std::endl;
		std::clog << "    git config wallet.signer <path-to-signer>" << std::endl;
		return 1;
	}

	// Check that age is available
	if (!age_is_available()) {
		std::clog << "Error: 'age' command not found. Please install age (https://age-encryption.org)." << std::endl;
		return 1;
	}

	// Build challenge message and have user sign it
	std::string	challenge = wallet_challenge_message();
	std::clog << "Signing challenge with wallet " << address << "..." << std::endl;
	std::clog << "Challenge: " << challenge << std::endl;

	std::string	signature;
	try {
		signature = wallet_sign_message(address, challenge);
	} catch (const Wallet_error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	// Derive age identity from signature
	std::string	identity_hex = wallet_derive_age_identity(signature);

	// Derive age recipient (public key) from the identity
	std::string	recipient;
	try {
		recipient = wallet_derive_age_recipient(identity_hex);
	} catch (const Wallet_error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	std::clog << "Derived age recipient: " << recipient << std::endl;

	// Load the symmetric key
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

	// Encrypt the key for the wallet-derived age recipient
	// Store under .git-crypt/keys/<name>/<version>/wallet/<address>.age
	std::string	key_file_data;
	{
		Key_file	this_version_key_file;
		this_version_key_file.set_key_name(key_name);
		this_version_key_file.add(*key);
		key_file_data = this_version_key_file.store_to_string();
	}

	const std::string		state_path(get_repo_state_path());
	const std::string		keys_path(get_repo_keys_path(state_path));
	std::vector<std::string>	new_files;

	std::ostringstream	path_builder;
	path_builder << keys_path << '/' << (key_name ? key_name : "default") << '/' << key->version << "/wallet/" << address << ".age";
	std::string		path(path_builder.str());

	if (access(path.c_str(), F_OK) == 0) {
		std::clog << "Wallet recipient " << address << " is already added." << std::endl;
		return 0;
	}

	mkdir_parent(path);
	age_encrypt_to_file(path, recipient, key_file_data.data(), key_file_data.size());
	new_files.push_back(path);

	// Write a metadata file with the address-to-recipient mapping
	std::ostringstream	meta_path_builder;
	meta_path_builder << keys_path << '/' << (key_name ? key_name : "default") << '/' << key->version << "/wallet/" << address << ".meta";
	std::string		meta_path(meta_path_builder.str());

	{
		std::ofstream	meta_file(meta_path.c_str());
		meta_file << "address=" << address << std::endl;
		meta_file << "recipient=" << recipient << std::endl;
		meta_file.close();
		if (meta_file) {
			new_files.push_back(meta_path);
		}
	}

	// Ensure .gitattributes in the state directory
	const std::string		state_gitattributes_path(state_path + "/.gitattributes");
	if (access(state_gitattributes_path.c_str(), F_OK) != 0) {
		std::ofstream		state_gitattributes_file(state_gitattributes_path.c_str());
		state_gitattributes_file << "# Do not edit this file.  To specify the files to encrypt, create your own\n";
		state_gitattributes_file << "# .gitattributes file in the directory where your files are.\n";
		state_gitattributes_file << "* !filter !diff\n";
		state_gitattributes_file << "*.gpg binary\n";
		state_gitattributes_file << "*.age binary\n";
		state_gitattributes_file.close();
		if (!state_gitattributes_file) {
			std::clog << "Error: unable to write " << state_gitattributes_path << std::endl;
			return 1;
		}
		new_files.push_back(state_gitattributes_path);
	}

	// add/commit the new files
	if (!new_files.empty()) {
		std::vector<std::string>	command;
		command.push_back("git");
		command.push_back("add");
		command.push_back("--");
		command.insert(command.end(), new_files.begin(), new_files.end());
		if (!successful_exit(exec_command(command))) {
			std::clog << "Error: 'git add' failed" << std::endl;
			return 1;
		}

		if (!no_commit) {
			std::ostringstream	commit_message_builder;
			commit_message_builder << "Add wallet recipient " << address << " to git-crypt";
			if (key_name) {
				commit_message_builder << " key '" << key_name << "'";
			}
			commit_message_builder << "\n\nWallet address: " << address;
			commit_message_builder << "\nDerived age recipient: " << recipient << "\n";

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

	std::clog << "Wallet recipient " << address << " added successfully." << std::endl;

	// Clear sensitive data
	explicit_memset(&identity_hex[0], 0, identity_hex.size());
	explicit_memset(&key_file_data[0], 0, key_file_data.size());

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

void help_split_key (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt split-key [OPTIONS] -o PREFIX" << std::endl;
	out << std::endl;
	out << "    -m, --threshold M        Minimum shares needed to reconstruct (default: 3)" << std::endl;
	out << "    -n, --shares N           Total number of shares to generate (default: 5)" << std::endl;
	out << "    -o, --output PREFIX      Output file prefix (required)" << std::endl;
	out << "    -k, --key-name KEYNAME   Split the given key, instead of the default" << std::endl;
	out << std::endl;
	out << "Splits the symmetric key into N Shamir shares, of which any M are sufficient" << std::endl;
	out << "to reconstruct the key.  Share files are written as PREFIX.1, PREFIX.2, etc." << std::endl;
	out << std::endl;
	out << "Use 'git-crypt unlock --shares FILE1 FILE2 ...' to reconstruct and unlock." << std::endl;
}
int split_key (int argc, const char** argv)
{
	const char*		key_name = 0;
	const char*		threshold_str = 0;
	const char*		shares_str = 0;
	const char*		output_prefix = 0;
	Options_list		options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("-m", &threshold_str));
	options.push_back(Option_def("--threshold", &threshold_str));
	options.push_back(Option_def("-n", &shares_str));
	options.push_back(Option_def("--shares", &shares_str));
	options.push_back(Option_def("-o", &output_prefix));
	options.push_back(Option_def("--output", &output_prefix));

	parse_options(options, argc, argv);

	if (!output_prefix) {
		std::clog << "Error: -o/--output prefix is required" << std::endl;
		help_split_key(std::clog);
		return 2;
	}

	// Parse threshold and shares (defaults: 3-of-5)
	uint8_t		threshold = 3;
	uint8_t		total = 5;

	if (threshold_str) {
		char*		end = 0;
		unsigned long	val = std::strtoul(threshold_str, &end, 10);
		if (end == threshold_str || *end != '\0' || val < 2 || val > 255) {
			std::clog << "Error: invalid threshold: " << threshold_str << " (must be 2-255)" << std::endl;
			return 2;
		}
		threshold = static_cast<uint8_t>(val);
	}
	if (shares_str) {
		char*		end = 0;
		unsigned long	val = std::strtoul(shares_str, &end, 10);
		if (end == shares_str || *end != '\0' || val < 2 || val > 255) {
			std::clog << "Error: invalid share count: " << shares_str << " (must be 2-255)" << std::endl;
			return 2;
		}
		total = static_cast<uint8_t>(val);
	}

	if (threshold > total) {
		std::clog << "Error: threshold (" << static_cast<int>(threshold) << ") must be <= total shares (" << static_cast<int>(total) << ")" << std::endl;
		return 2;
	}

	// Load the key file
	Key_file		key_file;
	load_key(key_file, key_name);

	// Serialize key to string
	std::string		key_data = key_file.store_to_string();

	// Split into shares
	std::vector<Shamir_share>	shares = shamir_split(key_data, threshold, total);

	// Write each share to a file
	for (uint8_t i = 0; i < total; ++i) {
		std::string	filename = std::string(output_prefix) + "." + std::to_string(i + 1);
		if (!shares[i].store_to_file(filename.c_str())) {
			std::clog << "Error: " << filename << ": unable to write share file" << std::endl;
			return 1;
		}
		std::cout << "Share " << static_cast<int>(i + 1) << "/" << static_cast<int>(total)
			  << " written to " << filename << std::endl;
	}

	std::cout << std::endl;
	std::cout << "Key split into " << static_cast<int>(total) << " shares (threshold: "
		  << static_cast<int>(threshold) << ")" << std::endl;
	std::cout << "Any " << static_cast<int>(threshold)
		  << " shares are sufficient to reconstruct the key." << std::endl;

	// Securely clear key data
	explicit_memset(&key_data[0], 0, key_data.size());

	return 0;
}

void help_sops_config (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt sops-config [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    -o, --output FILE          Write config to FILE (default: .sops.yaml)" << std::endl;
	out << "    -k, --key-name KEYNAME     Use recipients from the given key" << std::endl;
	out << "    -p, --pattern REGEX        File pattern for SOPS (repeatable)" << std::endl;
	out << std::endl;
	out << "Generate a .sops.yaml configuration that uses the same age recipients as" << std::endl;
	out << "git-crypt.  Structured files (YAML/JSON/ENV) matching the patterns will" << std::endl;
	out << "be encrypted by SOPS (partial encryption: keys visible, values encrypted)." << std::endl;
	out << std::endl;
	out << "Default patterns if none specified:" << std::endl;
	out << "    secrets\\.ya?ml$    secrets\\.json$    \\.env(\\..+)?$" << std::endl;
}
int sops_config (int argc, const char** argv)
{
	const char*		output_file = 0;
	const char*		key_name = 0;
	Options_list		options;
	options.push_back(Option_def("-o", &output_file));
	options.push_back(Option_def("--output", &output_file));
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));

	// Collect -p/--pattern arguments manually from remaining args
	int			argi = parse_options(options, argc, argv);

	// Check if sops is available
	if (!sops_is_available()) {
		std::clog << "Warning: sops is not installed or not in PATH." << std::endl;
		std::clog << "Install SOPS from https://github.com/getsops/sops" << std::endl;
		std::clog << "Generating .sops.yaml anyway..." << std::endl;
	}

	// Collect age recipients
	std::vector<std::string>	recipients = sops_collect_age_recipients(key_name);
	if (recipients.empty()) {
		std::clog << "Warning: no age recipients found." << std::endl;
		std::clog << "Set recipients via:" << std::endl;
		std::clog << "  git config git-crypt.sops-age-recipients 'age1...'" << std::endl;
		std::clog << "  export SOPS_AGE_RECIPIENTS='age1...'" << std::endl;
		std::clog << "  git-crypt add-age-recipient <RECIPIENT> first" << std::endl;
	}

	// File patterns: use remaining args or defaults
	std::vector<std::string>	patterns;
	for (int i = argi; i < argc; ++i) {
		patterns.push_back(argv[i]);
	}
	if (patterns.empty()) {
		patterns.push_back("secrets\\.ya?ml$");
		patterns.push_back("secrets\\.json$");
		patterns.push_back("\\.env(\\..+)?$");
	}

	// Output path
	std::string	out_path = output_file ? output_file : ".sops.yaml";

	if (!sops_generate_config(out_path, recipients, patterns)) {
		std::clog << "Error: " << out_path << ": unable to write config file" << std::endl;
		return 1;
	}

	std::cout << "SOPS config written to " << out_path << std::endl;
	if (!recipients.empty()) {
		std::cout << "Age recipients: " << recipients.size() << std::endl;
	}
	std::cout << "File patterns: " << patterns.size() << std::endl;
	std::cout << std::endl;
	std::cout << "To encrypt a file with SOPS:  sops -e -i secrets.yaml" << std::endl;
	std::cout << "To edit an encrypted file:    sops secrets.yaml" << std::endl;

	return 0;
}

void help_credentials_init (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt credentials-init [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --sops                      Also create .sops.yaml in .credentials/" << std::endl;
	out << std::endl;
	out << "Create a .credentials/ directory with pre-configured .gitattributes for" << std::endl;
	out << "git-crypt encryption, template files for common credential types, and" << std::endl;
	out << "optional SOPS integration for structured secrets." << std::endl;
}
int credentials_init (int argc, const char** argv)
{
	bool		setup_sops = false;
	Options_list	options;
	options.push_back(Option_def("--sops", &setup_sops));

	parse_options(options, argc, argv);

	// Create .credentials/ directory
	std::string	cred_dir = ".credentials";
	if (access(cred_dir.c_str(), F_OK) == 0) {
		std::clog << "Warning: .credentials/ directory already exists" << std::endl;
	}

	// Use mkdir -p via mkdir_parent on a child path, then create the dir itself
	std::string	marker_path = cred_dir + "/.gitattributes";
	mkdir_parent(marker_path);
	// mkdir_parent creates parents but not the last component — we need the dir itself
	mkdir(cred_dir.c_str(), 0700);

	// 1. Write .credentials/.gitattributes
	{
		std::ofstream	out(marker_path);
		if (!out) {
			std::clog << "Error: unable to write " << marker_path << std::endl;
			return 1;
		}
		out << "# git-crypt: encrypt all files in .credentials/" << std::endl;
		out << "* filter=git-crypt diff=git-crypt" << std::endl;
		out << ".gitattributes !filter !diff" << std::endl;
		out << "README.md !filter !diff" << std::endl;
		if (setup_sops) {
			out << ".sops.yaml !filter !diff" << std::endl;
		}
		out.close();
		if (!out.good()) {
			std::clog << "Error: failed to write " << marker_path << std::endl;
			return 1;
		}
	}
	std::cout << "Created " << marker_path << std::endl;

	// 2. Write .credentials/README.md
	{
		std::string	readme_path = cred_dir + "/README.md";
		std::ofstream	out(readme_path);
		if (out) {
			out << "# Credentials Directory" << std::endl;
			out << std::endl;
			out << "This directory is encrypted by git-crypt.  All files (except this" << std::endl;
			out << "README and .gitattributes) are transparently encrypted when pushed" << std::endl;
			out << "and decrypted when pulled." << std::endl;
			out << std::endl;
			out << "## Setup" << std::endl;
			out << std::endl;
			out << "1. Run `git-crypt unlock` to decrypt (requires authorized GPG/age key)" << std::endl;
			out << "2. Add secrets to the appropriate file below" << std::endl;
			out << "3. Commit and push — encryption happens automatically" << std::endl;
			out << std::endl;
			out << "## File Organization" << std::endl;
			out << std::endl;
			out << "- `env.production` — Production environment variables" << std::endl;
			out << "- `env.staging` — Staging environment variables" << std::endl;
			out << "- `api-keys.env` — API keys and tokens" << std::endl;
			out << "- `certificates/` — TLS/SSL certificates and private keys" << std::endl;
			out.close();
		}
		std::cout << "Created " << readme_path << std::endl;
	}

	// 3. Write template files
	{
		std::string	env_prod = cred_dir + "/env.production";
		std::ofstream	out(env_prod);
		if (out) {
			out << "# Production environment variables" << std::endl;
			out << "# This file is encrypted by git-crypt" << std::endl;
			out << std::endl;
			out << "# DATABASE_URL=postgresql://user:password@host:5432/dbname" << std::endl;
			out << "# API_SECRET_KEY=your-secret-key-here" << std::endl;
			out << "# AWS_ACCESS_KEY_ID=AKIA..." << std::endl;
			out << "# AWS_SECRET_ACCESS_KEY=..." << std::endl;
			out.close();
		}
		std::cout << "Created " << env_prod << std::endl;
	}
	{
		std::string	env_staging = cred_dir + "/env.staging";
		std::ofstream	out(env_staging);
		if (out) {
			out << "# Staging environment variables" << std::endl;
			out << "# This file is encrypted by git-crypt" << std::endl;
			out << std::endl;
			out.close();
		}
		std::cout << "Created " << env_staging << std::endl;
	}
	{
		std::string	api_keys = cred_dir + "/api-keys.env";
		std::ofstream	out(api_keys);
		if (out) {
			out << "# API keys and tokens" << std::endl;
			out << "# This file is encrypted by git-crypt" << std::endl;
			out << std::endl;
			out.close();
		}
		std::cout << "Created " << api_keys << std::endl;
	}

	// 4. Create certificates subdirectory
	{
		std::string	cert_dir = cred_dir + "/certificates";
		mkdir(cert_dir.c_str(), 0700);
		std::string	cert_readme = cert_dir + "/.gitkeep";
		std::ofstream	out(cert_readme);
		if (out) {
			out.close();
		}
		std::cout << "Created " << cert_dir << "/" << std::endl;
	}

	// 5. Optionally set up SOPS
	if (setup_sops) {
		std::vector<std::string>	recipients = sops_collect_age_recipients(0);
		std::vector<std::string>	patterns;
		patterns.push_back("secrets\\.ya?ml$");
		patterns.push_back("secrets\\.json$");
		std::string	sops_path = cred_dir + "/.sops.yaml";
		if (sops_generate_config(sops_path, recipients, patterns)) {
			std::cout << "Created " << sops_path << std::endl;
		}
	}

	std::cout << std::endl;
	std::cout << "Credentials directory initialized at .credentials/" << std::endl;
	std::cout << "All files in this directory are encrypted by git-crypt." << std::endl;

	return 0;
}

void help_audit_log (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt audit-log [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    -n, --limit N               Show only the last N entries" << std::endl;
	out << "    --verify                    Also verify hash chain integrity" << std::endl;
	out << std::endl;
	out << "Display the cryptographic audit trail of decrypt/encrypt operations." << std::endl;
}
int audit_log (int argc, const char** argv)
{
	const char*	limit_str = 0;
	bool		verify = false;
	Options_list	options;
	options.push_back(Option_def("-n", &limit_str));
	options.push_back(Option_def("--limit", &limit_str));
	options.push_back(Option_def("--verify", &verify));

	parse_options(options, argc, argv);

	std::vector<Audit_entry>	entries = audit_read_log();

	if (entries.empty()) {
		std::cout << "No audit log entries found." << std::endl;
		std::cout << "Audit log location: " << audit_log_path() << std::endl;
		return 0;
	}

	// Optional verification
	if (verify) {
		size_t	valid = audit_verify_chain(entries);
		if (valid == entries.size()) {
			std::cout << "Hash chain: VALID (" << valid << " entries)" << std::endl;
		} else {
			std::cout << "Hash chain: BROKEN at entry " << (valid + 1)
				  << " of " << entries.size() << std::endl;
		}
		std::cout << std::endl;
	}

	// Apply limit
	size_t	start = 0;
	if (limit_str) {
		char*		end = 0;
		unsigned long	n = std::strtoul(limit_str, &end, 10);
		if (end == limit_str || *end != '\0' || n == 0) {
			std::clog << "Error: invalid limit: " << limit_str << std::endl;
			return 2;
		}
		if (n < entries.size()) {
			start = entries.size() - n;
		}
	}

	// Display entries
	for (size_t i = start; i < entries.size(); ++i) {
		const Audit_entry&	e = entries[i];
		std::cout << "[" << (i + 1) << "] " << e.timestamp << std::endl;
		std::cout << "    Operation:  " << e.operation << std::endl;
		std::cout << "    Identity:   " << e.identity << " (" << e.identity_type << ")" << std::endl;
		std::cout << "    Key:        " << e.key_name << std::endl;
		if (!e.files.empty()) {
			std::cout << "    Files:      " << e.files.size() << std::endl;
		}
		std::cout << "    Hash:       " << e.entry_hash.substr(0, 16) << "..." << std::endl;
		std::cout << std::endl;
	}

	std::cout << "Total: " << entries.size() << " entries" << std::endl;
	return 0;
}

void help_verify_audit (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt verify-audit" << std::endl;
	out << std::endl;
	out << "Verify the integrity of the cryptographic audit trail hash chain." << std::endl;
	out << "Returns exit code 0 if the chain is valid, 1 if tampered." << std::endl;
}
int verify_audit (int argc, const char** argv)
{
	parse_options(Options_list(), argc, argv);

	std::vector<Audit_entry>	entries = audit_read_log();

	if (entries.empty()) {
		std::cout << "No audit log entries found." << std::endl;
		return 0;
	}

	size_t	valid = audit_verify_chain(entries);

	if (valid == entries.size()) {
		std::cout << "Audit log hash chain: VALID" << std::endl;
		std::cout << "Entries verified: " << valid << std::endl;
		std::cout << "First entry:     " << entries.front().timestamp << std::endl;
		std::cout << "Last entry:      " << entries.back().timestamp << std::endl;
		return 0;
	} else {
		std::cout << "Audit log hash chain: BROKEN" << std::endl;
		std::cout << "Valid entries:   " << valid << " of " << entries.size() << std::endl;
		if (valid > 0) {
			std::cout << "Last valid:      " << entries[valid - 1].timestamp << std::endl;
		}
		std::cout << "Tampered entry:  " << (valid + 1) << " (" << entries[valid].timestamp << ")" << std::endl;
		return 1;
	}
}

void help_anchor_audit (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt anchor-audit [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    --rpc-url URL               Ethereum JSON-RPC endpoint" << std::endl;
	out << "    --from ADDRESS              Ethereum address to send from" << std::endl;
	out << "    --list                      List previous on-chain anchors" << std::endl;
	out << std::endl;
	out << "Publish a SHA3-256 hash of the current audit log state to an" << std::endl;
	out << "Ethereum-compatible blockchain for immutable timestamping." << std::endl;
	out << std::endl;
	out << "Configuration:" << std::endl;
	out << "    git config audit.rpc-url URL    Default RPC endpoint" << std::endl;
	out << "    git config audit.from ADDRESS   Default sender address" << std::endl;
	out << "    git config wallet.signer PATH   Signing tool (default: cast)" << std::endl;
	out << std::endl;
}
int anchor_audit (int argc, const char** argv)
{
	const char*	rpc_url = 0;
	const char*	from_address = 0;
	bool		list_mode = false;
	Options_list	options;
	options.push_back(Option_def("--rpc-url", &rpc_url));
	options.push_back(Option_def("--from", &from_address));
	options.push_back(Option_def("--list", &list_mode));

	parse_options(options, argc, argv);

	if (list_mode) {
		// List previous anchors
		std::vector<Audit_anchor>	anchors = audit_read_anchors();
		if (anchors.empty()) {
			std::cout << "No on-chain anchors recorded." << std::endl;
			return 0;
		}
		for (size_t i = 0; i < anchors.size(); ++i) {
			const Audit_anchor&	a = anchors[i];
			std::cout << "[" << (i + 1) << "] " << a.timestamp << std::endl;
			std::cout << "    State hash:  " << a.state_hash.substr(0, 16) << "..." << std::endl;
			std::cout << "    Tx hash:     " << a.tx_hash << std::endl;
			std::cout << "    RPC URL:     " << a.rpc_url << std::endl;
			std::cout << "    Entries:     " << a.entry_count << std::endl;
			std::cout << std::endl;
		}
		std::cout << "Total: " << anchors.size() << " anchors" << std::endl;
		return 0;
	}

	// Resolve RPC URL
	std::string	rpc;
	if (rpc_url) {
		rpc = rpc_url;
	} else {
		try {
			rpc = get_git_config("audit.rpc-url");
		} catch (...) {
		}
	}
	if (rpc.empty()) {
		std::clog << "Error: no RPC URL specified." << std::endl;
		std::clog << "Use --rpc-url URL or: git config audit.rpc-url URL" << std::endl;
		return 2;
	}

	// Resolve from address
	std::string	from;
	if (from_address) {
		from = from_address;
	} else {
		try {
			from = get_git_config("audit.from");
		} catch (...) {
		}
	}
	if (from.empty()) {
		std::clog << "Error: no sender address specified." << std::endl;
		std::clog << "Use --from ADDRESS or: git config audit.from ADDRESS" << std::endl;
		return 2;
	}

	// Verify audit log integrity first
	std::vector<Audit_entry>	entries = audit_read_log();
	if (entries.empty()) {
		std::clog << "Error: audit log is empty. Nothing to anchor." << std::endl;
		return 1;
	}

	size_t	valid = audit_verify_chain(entries);
	if (valid != entries.size()) {
		std::clog << "Error: audit log hash chain is broken at entry " << (valid + 1) << "." << std::endl;
		std::clog << "Fix the audit log before anchoring." << std::endl;
		return 1;
	}

	// Compute state hash
	std::string	state_hash = audit_state_hash();
	std::cout << "Audit state hash: " << state_hash << std::endl;
	std::cout << "Entries:          " << entries.size() << std::endl;
	std::cout << "Anchoring to:     " << rpc << std::endl;
	std::cout << "From:             " << from << std::endl;

	// Publish on-chain
	std::string	tx_hash;
	try {
		tx_hash = audit_anchor_onchain(state_hash, rpc, from);
	} catch (const Error& e) {
		std::clog << "Error: " << e.message << std::endl;
		return 1;
	}

	if (tx_hash.empty()) {
		std::clog << "Warning: transaction sent but hash could not be parsed from output." << std::endl;
		std::clog << "Check the blockchain for the transaction." << std::endl;
		tx_hash = "unknown";
	}

	std::cout << "Transaction hash: " << tx_hash << std::endl;
	std::cout << "Anchor published successfully." << std::endl;

	// Record the anchor locally
	audit_record_anchor(state_hash, tx_hash, rpc, entries.size());

	// Also log the anchor operation in the audit trail itself
	std::string	identity_type;
	std::string	identity = audit_get_identity(identity_type);
	std::vector<std::string>	empty_files;
	audit_log_operation("anchor", identity, identity_type, 0, empty_files);

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

void help_install_hooks (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt install-hooks" << std::endl;
	out << std::endl;
	out << "    Install a pre-commit hook that prevents accidental commits of" << std::endl;
	out << "    plaintext files that should be encrypted by git-crypt." << std::endl;
	out << std::endl;
}
int install_hooks (int argc, const char** argv)
{
	if (argc != 0) {
		std::clog << "Error: git-crypt install-hooks takes no arguments" << std::endl;
		help_install_hooks(std::clog);
		return 2;
	}

	// Get the .git/hooks directory
	std::vector<std::string>	command;
	command.push_back("git");
	command.push_back("rev-parse");
	command.push_back("--git-dir");

	std::stringstream		output;
	if (!successful_exit(exec_command(command, output))) {
		throw Error("'git rev-parse --git-dir' failed - is this a Git repository?");
	}

	std::string			git_dir;
	std::getline(output, git_dir);
	std::string			hooks_dir(git_dir + "/hooks");

	// Ensure hooks directory exists
	mkdir_parent(hooks_dir + "/dummy");

	std::string			hook_dest(hooks_dir + "/pre-commit");

	// Check if a pre-commit hook already exists
	if (access(hook_dest.c_str(), F_OK) == 0) {
		std::clog << "Warning: " << hook_dest << " already exists." << std::endl;
		std::clog << "Overwriting with git-crypt pre-commit hook." << std::endl;
	}

	// Write the pre-commit hook inline
	std::ofstream			hook_file(hook_dest.c_str());
	if (!hook_file) {
		throw Error("Unable to create hook file: " + hook_dest);
	}

	hook_file << "#!/bin/sh\n";
	hook_file << "#\n";
	hook_file << "# git-crypt pre-commit hook\n";
	hook_file << "# Prevents accidental commits of plaintext files that should be encrypted.\n";
	hook_file << "#\n";
	hook_file << "set -e\n";
	hook_file << "\n";
	hook_file << "if ! git config --get-regexp '^filter\\.git-crypt' >/dev/null 2>&1; then\n";
	hook_file << "\texit 0\n";
	hook_file << "fi\n";
	hook_file << "\n";
	hook_file << "staged_files=$(git diff --cached --name-only --diff-filter=d)\n";
	hook_file << "if [ -z \"$staged_files\" ]; then\n";
	hook_file << "\texit 0\n";
	hook_file << "fi\n";
	hook_file << "\n";
	hook_file << "ERRORS=0\n";
	hook_file << "for file in $staged_files; do\n";
	hook_file << "\tfilter=$(git check-attr filter -- \"$file\" | sed 's/.*: //')\n";
	hook_file << "\tcase \"$filter\" in\n";
	hook_file << "\t\tgit-crypt|git-crypt-*) ;;\n";
	hook_file << "\t\t*) continue ;;\n";
	hook_file << "\tesac\n";
	hook_file << "\tblob_id=$(git ls-files -s -- \"$file\" | awk '{print $2}')\n";
	hook_file << "\tif [ -z \"$blob_id\" ]; then\n";
	hook_file << "\t\tcontinue\n";
	hook_file << "\tfi\n";
	hook_file << "\theader=$(git cat-file blob \"$blob_id\" | head -c 10 | od -A n -t x1 | tr -d ' \\n')\n";
	hook_file << "\tif [ \"$header\" != \"00474954435259505400\" ]; then\n";
	hook_file << "\t\techo \"ERROR: $file should be encrypted but is staged in PLAINTEXT!\" >&2\n";
	hook_file << "\t\tERRORS=$((ERRORS + 1))\n";
	hook_file << "\tfi\n";
	hook_file << "done\n";
	hook_file << "\n";
	hook_file << "if [ \"$ERRORS\" -gt 0 ]; then\n";
	hook_file << "\techo \"\" >&2\n";
	hook_file << "\techo \"Commit rejected: $ERRORS file(s) would be committed without encryption.\" >&2\n";
	hook_file << "\techo \"Run 'git-crypt status' to diagnose the issue.\" >&2\n";
	hook_file << "\texit 1\n";
	hook_file << "fi\n";
	hook_file << "exit 0\n";

	hook_file.close();
	if (!hook_file) {
		throw Error("Error writing hook file: " + hook_dest);
	}

	// Make the hook executable (on Unix)
#ifndef _WIN32
	if (chmod(hook_dest.c_str(), 0755) != 0) {
		throw System_error("chmod", hook_dest, errno);
	}
#endif

	std::cout << "Pre-commit hook installed to " << hook_dest << std::endl;
	return 0;
}

void help_verify_commits (std::ostream& out)
{
	//     |--------------------------------------------------------------------------------| 80 chars
	out << "Usage: git-crypt verify-commits [OPTIONS]" << std::endl;
	out << std::endl;
	out << "    -k, --key-name KEYNAME   Check commits for the given key (default: all)" << std::endl;
	out << "    -n, --max-count N        Check only the last N commits (default: all)" << std::endl;
	out << std::endl;
	out << "    Scans git history for commits that modified encrypted files and" << std::endl;
	out << "    reports which of those commits are not GPG-signed." << std::endl;
	out << std::endl;
}
int verify_commits (int argc, const char** argv)
{
	const char*	key_name = 0;
	const char*	max_count_str = 0;
	Options_list	options;
	options.push_back(Option_def("-k", &key_name));
	options.push_back(Option_def("--key-name", &key_name));
	options.push_back(Option_def("-n", &max_count_str));
	options.push_back(Option_def("--max-count", &max_count_str));

	int		argi = parse_options(options, argc, argv);

	if (argc - argi != 0) {
		std::clog << "Error: git-crypt verify-commits takes no positional arguments" << std::endl;
		help_verify_commits(std::clog);
		return 2;
	}

	// 1. Get the list of encrypted files (based on current .gitattributes)
	std::vector<std::string>	encrypted_files;
	if (key_name) {
		validate_key_name_or_throw(key_name);
		get_encrypted_files(encrypted_files, key_name);
	} else {
		// Check all keys by looking at the internal key store
		std::string	internal_keys_path;
		try {
			internal_keys_path = get_internal_keys_path();
		} catch (...) {
			// Not initialized — fall through to default key
		}
		if (!internal_keys_path.empty() && access(internal_keys_path.c_str(), F_OK) == 0) {
			std::vector<std::string>	dirents(get_directory_contents(internal_keys_path.c_str()));
			for (std::vector<std::string>::const_iterator dirent(dirents.begin()); dirent != dirents.end(); ++dirent) {
				const char* this_key_name = (*dirent == "default" ? 0 : dirent->c_str());
				get_encrypted_files(encrypted_files, this_key_name);
			}
		} else {
			// Fallback: check files for default key
			get_encrypted_files(encrypted_files, 0);
		}
	}

	if (encrypted_files.empty()) {
		std::cout << "No encrypted files found." << std::endl;
		return 0;
	}

	// 2. Build a set of encrypted file paths for fast lookup
	std::set<std::string>	encrypted_set(encrypted_files.begin(), encrypted_files.end());

	// 3. Get commits with signature status and changed files
	// %G? signature status: G=good, B=bad, U=untrusted, X=expired, Y=expired key,
	//                       R=revoked, E=cannot check, N=no signature
	std::vector<std::string>	log_command;
	log_command.push_back("git");
	log_command.push_back("log");
	log_command.push_back("--format=%H:%G?:%an:%s");
	log_command.push_back("--name-only");
	if (max_count_str) {
		log_command.push_back(std::string("--max-count=") + max_count_str);
	}

	std::stringstream		log_output;
	if (!successful_exit(exec_command(log_command, log_output))) {
		throw Error("'git log' failed - is this a Git repository?");
	}

	// 4. Parse the log output and check each commit
	unsigned int	total_commits = 0;
	unsigned int	unsigned_commits = 0;
	unsigned int	signed_commits = 0;

	std::string	line;
	std::string	current_hash;
	std::string	current_sig;
	std::string	current_author;
	std::string	current_subject;
	bool		current_touches_encrypted = false;
	bool		first_commit = true;

	while (std::getline(log_output, line)) {
		if (line.empty()) {
			continue;
		}

		// Detect commit header lines: 40-char hex hash followed by ':'sig':'
		bool	is_commit_header = false;
		if (line.length() > 42 && line[40] == ':' && line[42] == ':') {
			is_commit_header = true;
			for (int i = 0; i < 40 && is_commit_header; ++i) {
				char c = line[i];
				is_commit_header = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
			}
		}

		if (is_commit_header) {
			// Report on previous commit if it touched encrypted files
			if (!first_commit && current_touches_encrypted) {
				++total_commits;
				if (current_sig == "N" || current_sig == "E") {
					++unsigned_commits;
					std::cout << "UNSIGNED: " << current_hash.substr(0, 12) << " " << current_author << ": " << current_subject << std::endl;
				} else if (current_sig == "B" || current_sig == "R") {
					++unsigned_commits;
					std::cout << "BAD SIG:  " << current_hash.substr(0, 12) << " " << current_author << ": " << current_subject << std::endl;
				} else {
					++signed_commits;
				}
			}

			// Parse the new commit header
			current_hash = line.substr(0, 40);
			current_sig = std::string(1, line[41]);
			std::string::size_type author_end = line.find(':', 43);
			if (author_end != std::string::npos) {
				current_author = line.substr(43, author_end - 43);
				current_subject = line.substr(author_end + 1);
			} else {
				current_author = "";
				current_subject = line.substr(43);
			}
			current_touches_encrypted = false;
			first_commit = false;
		} else if (!first_commit) {
			// This is a filename from --name-only
			if (encrypted_set.count(line) > 0) {
				current_touches_encrypted = true;
			}
		}
	}

	// Process the last commit
	if (!first_commit && current_touches_encrypted) {
		++total_commits;
		if (current_sig == "N" || current_sig == "E") {
			++unsigned_commits;
			std::cout << "UNSIGNED: " << current_hash.substr(0, 12) << " " << current_author << ": " << current_subject << std::endl;
		} else if (current_sig == "B" || current_sig == "R") {
			++unsigned_commits;
			std::cout << "BAD SIG:  " << current_hash.substr(0, 12) << " " << current_author << ": " << current_subject << std::endl;
		} else {
			++signed_commits;
		}
	}

	// 5. Print summary
	std::cout << std::endl;
	std::cout << total_commits << " commit" << (total_commits != 1 ? "s" : "") << " touched encrypted files: ";
	std::cout << signed_commits << " signed, " << unsigned_commits << " unsigned/bad" << std::endl;

	if (unsigned_commits > 0) {
		std::cout << std::endl;
		std::cout << "Warning: unsigned commits that modify encrypted files may indicate" << std::endl;
		std::cout << "unauthorized changes. Review these commits carefully." << std::endl;
		return 1;
	}

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

	// Stream git ls-files output via Coprocess to avoid buffering all
	// output into memory (significant for repos with thousands of files).
	Coprocess			ls_files;
	std::istream*			ls_files_stdout = ls_files.stdout_pipe();
	ls_files.spawn(command);

	// Output looks like (w/o newlines):
	// ? .gitignore\0
	// H 100644 06ec22e5ed0de9280731ef000a10f9c3fbc26338 0     afile\0

	std::vector<std::string>	files;
	bool				attribute_errors = false;
	bool				unencrypted_blob_errors = false;
	bool				tamper_warnings = false;
	unsigned int			nbr_of_fixed_blobs = 0;
	unsigned int			nbr_of_fix_errors = 0;

	// Batch attribute querying: use a single persistent git check-attr process
	// for Git >= 1.8.5, avoiding one subprocess per file.
	Coprocess			check_attr;
	std::ostream*			check_attr_stdin = nullptr;
	std::istream*			check_attr_stdout = nullptr;
	if (git_version() >= make_version(1, 8, 5)) {
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
		std::string		tag;
		std::string		object_id;
		std::string		filename;
		*ls_files_stdout >> tag;
		if (tag != "?") {
			std::string	mode;
			std::string	stage;
			*ls_files_stdout >> mode >> object_id >> stage;
			if (!is_git_file_mode(mode)) {
				continue;
			}
		}
		*ls_files_stdout >> std::ws;
		std::getline(*ls_files_stdout, filename, '\0');

		std::pair<std::string, std::string> file_attrs;
		if (check_attr_stdin) {
			file_attrs = get_file_attributes(filename, *check_attr_stdin, *check_attr_stdout);
		} else {
			file_attrs = get_file_attributes(filename);
		}

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

	// Clean up coprocesses
	if (check_attr_stdin) {
		check_attr.close_stdin();
		if (!successful_exit(check_attr.wait())) {
			throw Error("'git check-attr' failed - is this a Git repository?");
		}
	}
	if (!successful_exit(ls_files.wait())) {
		throw Error("'git ls-files' failed - is this a Git repository?");
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

