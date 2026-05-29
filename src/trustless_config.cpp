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

#include "trustless_config.hpp"
#include "commands.hpp"
#include "util.hpp"
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <sys/stat.h>

static std::string get_env (const char* name)
{
	const char* val = std::getenv(name);
	return val ? std::string(val) : std::string();
}

static std::vector<std::string> split_comma (const std::string& s)
{
	std::vector<std::string> result;
	std::stringstream ss(s);
	std::string item;
	while (std::getline(ss, item, ',')) {
		// Trim whitespace
		size_t start = item.find_first_not_of(" \t");
		size_t end = item.find_last_not_of(" \t");
		if (start != std::string::npos) {
			result.push_back(item.substr(start, end - start + 1));
		}
	}
	return result;
}

std::string trustless_git_config_get (const std::string& key)
{
	std::vector<std::string> command;
	command.push_back("git");
	command.push_back("config");
	command.push_back("--get");
	command.push_back(key);

	std::stringstream output;
	int status = exec_command(command, output);
	if (!successful_exit(status)) {
		return std::string();
	}

	std::string result = output.str();
	// Trim trailing newline
	while (!result.empty() && (result.back() == '\n' || result.back() == '\r')) {
		result.pop_back();
	}
	return result;
}

void trustless_git_config_set (const std::string& key, const std::string& value)
{
	std::vector<std::string> command;
	command.push_back("git");
	command.push_back("config");
	command.push_back(key);
	command.push_back(value);

	int status = exec_command(command);
	if (!successful_exit(status)) {
		throw Error("Failed to set git config " + key);
	}
}

std::string trustless_data_dir ()
{
	std::vector<std::string> command;
	command.push_back("git");
	command.push_back("rev-parse");
	command.push_back("--show-toplevel");

	std::stringstream output;
	int status = exec_command(command, output);
	if (!successful_exit(status)) {
		throw Error("Not a git repository");
	}

	std::string repo_root = output.str();
	while (!repo_root.empty() && (repo_root.back() == '\n' || repo_root.back() == '\r')) {
		repo_root.pop_back();
	}

	return repo_root + "/.git-crypt/trustless";
}

bool trustless_initialized ()
{
	std::string rpc = trustless_git_config_get("trustless.rpc-url");
	std::string registry = trustless_git_config_get("trustless.registry-address");
	return !rpc.empty() && !registry.empty();
}

Trustless_config trustless_config_load_partial ()
{
	Trustless_config cfg;

	// Environment variables (higher precedence)
	std::string env_rpc = get_env("GIT_CRYPT_TRUSTLESS_RPC_URL");
	std::string env_rpcs = get_env("GIT_CRYPT_TRUSTLESS_RPC_URLS");
	std::string env_threshold = get_env("GIT_CRYPT_TRUSTLESS_RPC_THRESHOLD");
	std::string env_chain = get_env("GIT_CRYPT_TRUSTLESS_CHAIN_ID");
	std::string env_registry = get_env("GIT_CRYPT_TRUSTLESS_REGISTRY_ADDRESS");
	std::string env_audit = get_env("GIT_CRYPT_TRUSTLESS_AUDIT_ADDRESS");
	std::string env_from = get_env("GIT_CRYPT_TRUSTLESS_FROM_ADDRESS");
	std::string env_key = get_env("GIT_CRYPT_TRUSTLESS_PRIVATE_KEY");

	// Git config values (lower precedence)
	std::string git_rpc = trustless_git_config_get("trustless.rpc-url");
	std::string git_rpcs = trustless_git_config_get("trustless.rpc-urls");
	std::string git_threshold = trustless_git_config_get("trustless.rpc-threshold");
	std::string git_chain = trustless_git_config_get("trustless.chain-id");
	std::string git_registry = trustless_git_config_get("trustless.registry-address");
	std::string git_audit = trustless_git_config_get("trustless.audit-address");
	std::string git_from = trustless_git_config_get("trustless.from-address");

	// Resolve: env > git config
	cfg.rpc_url = !env_rpc.empty() ? env_rpc : git_rpc;
	cfg.chain_id = !env_chain.empty() ? env_chain : git_chain;
	cfg.registry_address = !env_registry.empty() ? env_registry : git_registry;
	cfg.audit_address = !env_audit.empty() ? env_audit : git_audit;
	cfg.from_address = !env_from.empty() ? env_from : git_from;
	cfg.private_key = env_key;  // Never from git config

	// Multi-RPC
	std::string rpcs_str = !env_rpcs.empty() ? env_rpcs : git_rpcs;
	if (!rpcs_str.empty()) {
		cfg.rpc_urls = split_comma(rpcs_str);
	}

	std::string threshold_str = !env_threshold.empty() ? env_threshold : git_threshold;
	if (!threshold_str.empty()) {
		cfg.rpc_threshold = std::atoi(threshold_str.c_str());
	} else {
		cfg.rpc_threshold = 0;
	}

	return cfg;
}

Trustless_config trustless_config_load ()
{
	Trustless_config cfg = trustless_config_load_partial();

	if (cfg.rpc_url.empty() && cfg.rpc_urls.empty()) {
		throw Error("No RPC URL configured. Set trustless.rpc-url in git config or GIT_CRYPT_TRUSTLESS_RPC_URL env var.");
	}
	if (cfg.registry_address.empty()) {
		throw Error("No registry address configured. Run 'git-crypt-trustless init' or set trustless.registry-address.");
	}

	// If single rpc_url is set but rpc_urls is empty, use it as the sole URL
	if (cfg.rpc_urls.empty() && !cfg.rpc_url.empty()) {
		cfg.rpc_urls.push_back(cfg.rpc_url);
	}

	// Default threshold: all must agree (or 1 if single URL)
	if (cfg.rpc_threshold <= 0) {
		cfg.rpc_threshold = static_cast<int>(cfg.rpc_urls.size());
	}

	return cfg;
}
