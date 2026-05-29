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

#include "trustless_rpc.hpp"
#include "trustless_config.hpp"
#include "trustless_chain.hpp"
#include "commands.hpp"
#include "util.hpp"
#include <map>
#include <iostream>
#include <sstream>

bool trustless_rpc_is_multi (const Trustless_config& cfg)
{
	return cfg.rpc_urls.size() > 1;
}

std::string trustless_rpc_consensus_call (const Trustless_config& cfg,
					   const std::string& contract_address,
					   const std::string& function_sig,
					   const std::vector<std::string>& args)
{
	if (!trustless_rpc_is_multi(cfg)) {
		return trustless_cast_call(cfg, contract_address, function_sig, args);
	}

	// Query each RPC and collect results
	std::map<std::string, int> result_counts;
	std::vector<std::string> results;
	int success_count = 0;

	for (size_t i = 0; i < cfg.rpc_urls.size(); ++i) {
		Trustless_config single_cfg = cfg;
		single_cfg.rpc_url = cfg.rpc_urls[i];

		try {
			std::string result = trustless_cast_call(single_cfg, contract_address, function_sig, args);
			results.push_back(result);
			result_counts[result]++;
			success_count++;
		} catch (const Error& e) {
			std::cerr << "Warning: RPC " << cfg.rpc_urls[i] << " failed: " << e.message << std::endl;
			results.push_back("");
		}
	}

	// Find the result with the most agreement
	std::string best_result;
	int best_count = 0;
	for (std::map<std::string, int>::const_iterator it = result_counts.begin();
	     it != result_counts.end(); ++it) {
		if (it->second > best_count) {
			best_count = it->second;
			best_result = it->first;
		}
	}

	// Check if consensus threshold is met
	if (best_count < cfg.rpc_threshold) {
		std::stringstream err;
		err << "Multi-RPC consensus failed: " << best_count << "/" << cfg.rpc_urls.size()
		    << " RPCs agreed (threshold: " << cfg.rpc_threshold << ")";
		throw Error(err.str());
	}

	// Log disagreements
	if (best_count < static_cast<int>(cfg.rpc_urls.size())) {
		std::cerr << "Warning: RPC disagreement detected. "
			  << best_count << "/" << cfg.rpc_urls.size() << " RPCs agreed." << std::endl;
	}

	return best_result;
}

Rpc_verify_result trustless_rpc_consensus_verify (const Trustless_config& cfg,
						    const std::string& id_hex)
{
	Rpc_verify_result out;
	out.valid = false;
	out.status = 0;
	out.expires_at = 0;
	out.consensus_reached = false;
	out.agreeing_count = 0;
	out.total_count = static_cast<int>(cfg.rpc_urls.size());

	if (!trustless_rpc_is_multi(cfg)) {
		Chain_verify_result single = trustless_chain_verify(cfg, id_hex);
		out.valid = single.valid;
		out.status = single.status;
		out.expires_at = single.expires_at;
		out.consensus_reached = true;
		out.agreeing_count = 1;
		out.total_count = 1;
		return out;
	}

	// Query each RPC
	struct VerifyResponse {
		bool valid;
		uint8_t status;
		uint64_t expires_at;
	};

	// Use a string key for grouping identical responses
	std::map<std::string, int> response_counts;
	std::map<std::string, VerifyResponse> response_data;

	for (size_t i = 0; i < cfg.rpc_urls.size(); ++i) {
		Trustless_config single_cfg = cfg;
		single_cfg.rpc_url = cfg.rpc_urls[i];

		try {
			Chain_verify_result r = trustless_chain_verify(single_cfg, id_hex);

			std::stringstream key;
			key << (r.valid ? "1" : "0") << ":" << static_cast<int>(r.status) << ":" << r.expires_at;
			std::string k = key.str();

			response_counts[k]++;
			VerifyResponse vr;
			vr.valid = r.valid;
			vr.status = r.status;
			vr.expires_at = r.expires_at;
			response_data[k] = vr;
		} catch (const Error& e) {
			std::cerr << "Warning: RPC " << cfg.rpc_urls[i] << " failed: " << e.message << std::endl;
		}
	}

	// Find best consensus
	std::string best_key;
	int best_count = 0;
	for (std::map<std::string, int>::const_iterator it = response_counts.begin();
	     it != response_counts.end(); ++it) {
		if (it->second > best_count) {
			best_count = it->second;
			best_key = it->first;
		}
	}

	out.agreeing_count = best_count;

	if (best_count >= cfg.rpc_threshold) {
		out.consensus_reached = true;
		const VerifyResponse& vr = response_data[best_key];
		out.valid = vr.valid;
		out.status = vr.status;
		out.expires_at = vr.expires_at;
	} else {
		std::cerr << "Warning: Multi-RPC consensus failed for verify. "
			  << best_count << "/" << cfg.rpc_urls.size() << " agreed." << std::endl;
	}

	return out;
}
