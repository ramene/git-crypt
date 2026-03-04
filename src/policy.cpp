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

#include "policy.hpp"
#include "util.hpp"
#include "commands.hpp"
#include <fstream>
#include <sstream>

// Policy file format (.git-crypt/policy.txt):
// Line-based, tab-separated fields.
// Record types:
//   owner\tFINGERPRINT\tNAME
//   member\tFINGERPRINT\tNAME\tSSH_PUBKEY_PATH
//   agent\tNAME\tKEY_SCOPES\tAGE_RECIPIENT
//   quorum\tOPERATION\tREQUIRED
//
// KEY_SCOPES is comma-separated list of key names (empty = none)

static std::string get_repo_root ()
{
	std::vector<std::string>	cmd;
	cmd.push_back("git");
	cmd.push_back("rev-parse");
	cmd.push_back("--show-toplevel");
	std::stringstream	output;
	if (successful_exit(exec_command(cmd, output))) {
		std::string	root = output.str();
		while (!root.empty() && (root.back() == '\n' || root.back() == '\r')) {
			root.pop_back();
		}
		return root;
	}
	return ".";
}

std::string policy_path ()
{
	return get_repo_root() + "/.git-crypt/policy.txt";
}

bool policy_exists ()
{
	std::ifstream	in(policy_path());
	return in.good();
}

static std::vector<std::string> split_tabs (const std::string& line)
{
	std::vector<std::string>	fields;
	size_t		pos = 0;
	while (pos <= line.size()) {
		size_t	next = line.find('\t', pos);
		if (next == std::string::npos) {
			fields.push_back(line.substr(pos));
			break;
		}
		fields.push_back(line.substr(pos, next - pos));
		pos = next + 1;
	}
	return fields;
}

static std::vector<std::string> split_commas (const std::string& s)
{
	std::vector<std::string>	result;
	if (s.empty()) return result;
	size_t		pos = 0;
	while (pos <= s.size()) {
		size_t	next = s.find(',', pos);
		if (next == std::string::npos) {
			result.push_back(s.substr(pos));
			break;
		}
		result.push_back(s.substr(pos, next - pos));
		pos = next + 1;
	}
	return result;
}

Policy policy_load ()
{
	Policy		policy;
	std::string	path = policy_path();
	std::ifstream	in(path);
	if (!in) {
		return policy;
	}

	std::string	line;
	while (std::getline(in, line)) {
		if (line.empty() || line[0] == '#') {
			continue;
		}
		std::vector<std::string>	fields = split_tabs(line);
		if (fields.empty()) continue;

		if (fields[0] == "owner" && fields.size() >= 3) {
			Policy_owner	o;
			o.fingerprint = fields[1];
			o.name = fields[2];
			policy.owners.push_back(o);
		} else if (fields[0] == "member" && fields.size() >= 4) {
			Policy_member	m;
			m.fingerprint = fields[1];
			m.name = fields[2];
			m.ssh_pubkey_path = fields[3];
			policy.members.push_back(m);
		} else if (fields[0] == "agent" && fields.size() >= 4) {
			Policy_agent	a;
			a.name = fields[1];
			a.key_scopes = split_commas(fields[2]);
			a.age_recipient = fields[3];
			policy.agents.push_back(a);
		} else if (fields[0] == "quorum" && fields.size() >= 3) {
			Policy_quorum	q;
			q.operation = fields[1];
			char*	end = 0;
			q.required = static_cast<int>(std::strtol(fields[2].c_str(), &end, 10));
			policy.quorums.push_back(q);
		}
	}
	return policy;
}

void policy_save (const Policy& policy)
{
	std::string	path = policy_path();
	mkdir_parent(path);

	std::ofstream	out(path);
	if (!out) {
		throw Error("Failed to write policy file: " + path);
	}

	out << "# git-crypt policy file" << std::endl;
	out << "# Format: type<TAB>field1<TAB>field2<TAB>..." << std::endl;

	for (size_t i = 0; i < policy.owners.size(); ++i) {
		out << "owner\t" << policy.owners[i].fingerprint
		    << '\t' << policy.owners[i].name << std::endl;
	}
	for (size_t i = 0; i < policy.members.size(); ++i) {
		out << "member\t" << policy.members[i].fingerprint
		    << '\t' << policy.members[i].name
		    << '\t' << policy.members[i].ssh_pubkey_path << std::endl;
	}
	for (size_t i = 0; i < policy.agents.size(); ++i) {
		out << "agent\t" << policy.agents[i].name << '\t';
		for (size_t j = 0; j < policy.agents[i].key_scopes.size(); ++j) {
			if (j > 0) out << ',';
			out << policy.agents[i].key_scopes[j];
		}
		out << '\t' << policy.agents[i].age_recipient << std::endl;
	}
	for (size_t i = 0; i < policy.quorums.size(); ++i) {
		out << "quorum\t" << policy.quorums[i].operation
		    << '\t' << policy.quorums[i].required << std::endl;
	}
}

bool policy_is_owner (const Policy& policy, const std::string& fingerprint)
{
	for (size_t i = 0; i < policy.owners.size(); ++i) {
		if (policy.owners[i].fingerprint == fingerprint) {
			return true;
		}
	}
	return false;
}

int policy_quorum_for (const Policy& policy, const std::string& operation)
{
	for (size_t i = 0; i < policy.quorums.size(); ++i) {
		if (policy.quorums[i].operation == operation) {
			return policy.quorums[i].required;
		}
	}
	// Also check wildcard "*" quorum
	for (size_t i = 0; i < policy.quorums.size(); ++i) {
		if (policy.quorums[i].operation == "*") {
			return policy.quorums[i].required;
		}
	}
	return 1;	// Default: single-party (no multi-party required)
}
