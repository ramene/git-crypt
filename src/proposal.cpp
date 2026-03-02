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

#include "proposal.hpp"
#include "util.hpp"
#include "commands.hpp"
#include <fstream>
#include <sstream>
#include <ctime>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/rand.h>

// Proposal file format (.git-crypt/proposals/<id>/proposal.txt):
// Line-based, tab-separated fields:
//   id\tVALUE
//   operation\tVALUE
//   timestamp\tVALUE
//   proposer\tFINGERPRINT
//   status\tVALUE
//   quorum\tN
//   param\tKEY\tVALUE
//
// Signatures stored in .git-crypt/proposals/<id>/signatures/<fingerprint>.sig

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

std::string proposals_dir ()
{
	return get_repo_root() + "/.git-crypt/proposals";
}

static std::string iso8601_now ()
{
	std::time_t	now = std::time(0);
	struct tm	tm_buf;
	gmtime_r(&now, &tm_buf);
	char		buf[32];
	std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
	return std::string(buf);
}

static std::string generate_proposal_id ()
{
	unsigned char	bytes[8];
	RAND_bytes(bytes, sizeof(bytes));
	static const char	hex_chars[] = "0123456789abcdef";
	std::string		result;
	result.reserve(16);
	for (int i = 0; i < 8; ++i) {
		result += hex_chars[(bytes[i] >> 4) & 0x0f];
		result += hex_chars[bytes[i] & 0x0f];
	}
	return result;
}

std::string proposal_create (const std::string& operation,
			     const std::string& proposer_fingerprint,
			     int quorum_required,
			     const std::map<std::string, std::string>& params)
{
	std::string	id = generate_proposal_id();
	std::string	dir = proposals_dir() + "/" + id;
	std::string	sig_dir = dir + "/signatures";

	// Create directories
	mkdir_parent(dir + "/proposal.txt");
	mkdir(dir.c_str(), 0755);
	mkdir(sig_dir.c_str(), 0755);

	Proposal	p;
	p.id = id;
	p.operation = operation;
	p.timestamp = iso8601_now();
	p.proposer_fingerprint = proposer_fingerprint;
	p.status = "pending";
	p.quorum_required = quorum_required;
	p.params = params;

	proposal_save(p);
	return id;
}

Proposal proposal_load (const std::string& id)
{
	Proposal	p;
	p.id = id;
	p.status = "unknown";
	p.quorum_required = 1;

	std::string	path = proposals_dir() + "/" + id + "/proposal.txt";
	std::ifstream	in(path);
	if (!in) {
		throw Error("Proposal not found: " + id);
	}

	std::string	line;
	while (std::getline(in, line)) {
		if (line.empty() || line[0] == '#') continue;

		size_t	tab = line.find('\t');
		if (tab == std::string::npos) continue;

		std::string	key = line.substr(0, tab);
		std::string	value = line.substr(tab + 1);

		if (key == "id") {
			p.id = value;
		} else if (key == "operation") {
			p.operation = value;
		} else if (key == "timestamp") {
			p.timestamp = value;
		} else if (key == "proposer") {
			p.proposer_fingerprint = value;
		} else if (key == "status") {
			p.status = value;
		} else if (key == "quorum") {
			char*	end = 0;
			p.quorum_required = static_cast<int>(std::strtol(value.c_str(), &end, 10));
		} else if (key == "param") {
			size_t	tab2 = value.find('\t');
			if (tab2 != std::string::npos) {
				p.params[value.substr(0, tab2)] = value.substr(tab2 + 1);
			}
		}
	}
	return p;
}

void proposal_save (const Proposal& proposal)
{
	std::string	path = proposals_dir() + "/" + proposal.id + "/proposal.txt";
	mkdir_parent(path);

	std::ofstream	out(path);
	if (!out) {
		throw Error("Failed to write proposal: " + path);
	}

	out << "id\t" << proposal.id << std::endl;
	out << "operation\t" << proposal.operation << std::endl;
	out << "timestamp\t" << proposal.timestamp << std::endl;
	out << "proposer\t" << proposal.proposer_fingerprint << std::endl;
	out << "status\t" << proposal.status << std::endl;
	out << "quorum\t" << proposal.quorum_required << std::endl;

	for (std::map<std::string, std::string>::const_iterator it = proposal.params.begin();
	     it != proposal.params.end(); ++it) {
		out << "param\t" << it->first << '\t' << it->second << std::endl;
	}
}

void proposal_approve (const std::string& id,
		       const std::string& fingerprint,
		       const std::string& signature)
{
	std::string	sig_path = proposals_dir() + "/" + id + "/signatures/" + fingerprint + ".sig";
	mkdir_parent(sig_path);

	std::ofstream	out(sig_path);
	if (!out) {
		throw Error("Failed to write approval signature: " + sig_path);
	}
	out << signature;
}

bool proposal_has_quorum (const std::string& id)
{
	Proposal	p = proposal_load(id);
	std::vector<std::string>	approvals = proposal_get_approvals(id);
	return static_cast<int>(approvals.size()) >= p.quorum_required;
}

std::vector<std::string> proposal_get_approvals (const std::string& id)
{
	std::vector<std::string>	result;
	std::string	sig_dir = proposals_dir() + "/" + id + "/signatures";

	if (access(sig_dir.c_str(), F_OK) != 0) {
		return result;
	}

	std::vector<std::string>	entries = get_directory_contents(sig_dir.c_str());
	for (size_t i = 0; i < entries.size(); ++i) {
		// Strip .sig extension to get fingerprint
		const std::string&	name = entries[i];
		if (name.size() > 4 && name.substr(name.size() - 4) == ".sig") {
			result.push_back(name.substr(0, name.size() - 4));
		}
	}
	return result;
}

std::vector<Proposal> proposal_list (const std::string& status_filter)
{
	std::vector<Proposal>	result;
	std::string		dir = proposals_dir();

	if (access(dir.c_str(), F_OK) != 0) {
		return result;
	}

	std::vector<std::string>	entries = get_directory_contents(dir.c_str());
	for (size_t i = 0; i < entries.size(); ++i) {
		std::string	proposal_file = dir + "/" + entries[i] + "/proposal.txt";
		std::ifstream	test(proposal_file);
		if (!test.good()) continue;
		test.close();

		try {
			Proposal	p = proposal_load(entries[i]);
			if (status_filter.empty() || p.status == status_filter) {
				result.push_back(p);
			}
		} catch (...) {
			// Skip malformed proposals
		}
	}
	return result;
}
