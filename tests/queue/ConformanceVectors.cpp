/*
 *  This file is part of nzbget. See <https://nzbget.com>.
 *
 *  Copyright (C) 2026 Denis <denis@nzbget.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <https://www.gnu.org/licenses/>.
 */


#include "nzbget.h"

#include <boost/json.hpp>
#include <boost/test/unit_test.hpp>
#include <openssl/sha.h>

#include <filesystem>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

/*
 * Conformance checks over the vendored yEnc encryption standards v1.2 test
 * vector fixtures (tests/testdata/test-vectors/, byte-identical copies of the
 * canonical set pinned by manifest.json). Fixture-driven via Boost.JSON:
 * nzb_segment_identity.json (VEC-06), index_allocation.json (VEC-07) and
 * malformed_inputs.json (VEC-05) shapes. Cryptographic round-trips are
 * deferred to the decryption milestone.
 */

namespace
{

std::string LoadFixtureText(const std::string& filename)
{
	namespace fs = std::filesystem;
	const std::vector<fs::path> candidates = {
		fs::path(__FILE__).parent_path() / ".." / "testdata" / "test-vectors" / filename,
		fs::current_path() / "testdata" / "test-vectors" / filename,
		fs::current_path() / "queue" / "testdata" / "test-vectors" / filename
	};
	for (const auto& path : candidates)
	{
		std::ifstream input(path, std::ios::binary);
		if (input)
		{
			std::ostringstream buffer;
			buffer << input.rdbuf();
			return buffer.str();
		}
	}
	BOOST_FAIL(("Fixture not found: " + filename).c_str());
	return "";
}

boost::json::value LoadFixture(const std::string& filename)
{
	const std::string text = LoadFixtureText(filename);
	boost::system::error_code errorCode;
	boost::json::value parsed = boost::json::parse(text, errorCode);
	BOOST_REQUIRE_MESSAGE(!errorCode, ("Failed to parse fixture " + filename + ": " + errorCode.message()).c_str());
	return parsed;
}

std::string JsonToString(const boost::json::value& value)
{
	BOOST_REQUIRE(value.is_string());
	return std::string(value.as_string().c_str());
}

std::string Sha256Hex(const std::string& content)
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX context;
	SHA256_Init(&context);
	SHA256_Update(&context, content.data(), content.size());
	SHA256_Final(digest, &context);

	static const char hex[] = "0123456789abcdef";
	std::string result;
	result.reserve(SHA256_DIGEST_LENGTH * 2);
	for (unsigned char byte : digest)
	{
		result.push_back(hex[byte >> 4]);
		result.push_back(hex[byte & 0x0F]);
	}
	return result;
}

bool Contains(const std::string& haystack, const std::string& needle)
{
	return haystack.find(needle) != std::string::npos;
}

}

BOOST_AUTO_TEST_SUITE(QueueTest)

BOOST_AUTO_TEST_CASE(ConformanceManifestSyncTest)
{
	boost::json::value manifest = LoadFixture("manifest.json");
	BOOST_CHECK_EQUAL(JsonToString(manifest.at("standard_version")), "1.2");

	const boost::json::object& files = manifest.at("files").as_object();
	BOOST_CHECK_EQUAL(files.size(), 7);

	const std::vector<std::string> expected = {
		"argon2id.json",
		"body_encryption.json",
		"control_line_encryption.json",
		"index_allocation.json",
		"malformed_inputs.json",
		"nonce_tweak.json",
		"nzb_segment_identity.json"
	};
	for (const std::string& name : expected)
	{
		BOOST_CHECK_MESSAGE(files.contains(name), ("manifest missing " + name).c_str());
		const std::string content = LoadFixtureText(name);
		BOOST_CHECK_EQUAL(Sha256Hex(content), JsonToString(files.at(name).at("sha256")));
	}
}

BOOST_AUTO_TEST_CASE(ConformanceIndexAllocationTest)
{
	// VEC-07: segmentIndex whose 4-byte BE encoding contains 0x0A / 0x0D is
	// forbidden; the uploader skips forward to the next permitted index.
	boost::json::value fixture = LoadFixture("index_allocation.json");
	const boost::json::array& vectors = fixture.at("vectors").as_array();
	BOOST_CHECK_EQUAL(vectors.size(), 4);

	for (const boost::json::value& entry : vectors)
	{
		const boost::json::object& vector = entry.as_object();
		const unsigned int candidate = vector.at("candidate_index").to_number<unsigned int>();
		const unsigned int assigned = vector.at("expected_assigned_index").to_number<unsigned int>();
		const std::string assignedHex = vector.at("expected_index_hex").as_string().c_str();

		// Forbidden byte must be present in the candidate's BE encoding.
		unsigned int be = candidate;
		unsigned char bytes[4] = {
			(unsigned char)((be >> 24) & 0xFF),
			(unsigned char)((be >> 16) & 0xFF),
			(unsigned char)((be >> 8) & 0xFF),
			(unsigned char)(be & 0xFF)
		};
		bool candidateForbidden = false;
		for (unsigned char byte : bytes)
		{
			if (byte == 0x0A || byte == 0x0D)
			{
				candidateForbidden = true;
			}
		}
		BOOST_CHECK(candidateForbidden);

		// Assigned index must be NNTP-safe and match the pinned hex.
		unsigned char assignedBytes[4] = {
			(unsigned char)((assigned >> 24) & 0xFF),
			(unsigned char)((assigned >> 16) & 0xFF),
			(unsigned char)((assigned >> 8) & 0xFF),
			(unsigned char)(assigned & 0xFF)
		};
		std::ostringstream hex;
		hex << std::hex << std::setfill('0');
		for (unsigned char byte : assignedBytes)
		{
			hex << std::setw(2) << (int)byte;
		}
		BOOST_CHECK_EQUAL(hex.str(), assignedHex);

		bool assignedForbidden = false;
		for (unsigned char byte : assignedBytes)
		{
			if (byte == 0x0A || byte == 0x0D)
			{
				assignedForbidden = true;
			}
		}
		BOOST_CHECK(!assignedForbidden);
	}

	// Index 269 itself is forbidden and must never be assigned.
	BOOST_CHECK_EQUAL(vectors[3].as_object().at("candidate_index").to_number<unsigned int>(), 269);
	BOOST_CHECK_EQUAL(vectors[3].as_object().at("expected_assigned_index").to_number<unsigned int>(), 270);
}

BOOST_AUTO_TEST_CASE(ConformanceNzbSegmentIdentityTest)
{
	// VEC-06: encrypted NZBs carry <meta type="yenc_encrypted">true</meta> and
	// <meta type="password">; ordinary NZBs carry neither and keep valid
	// identity with no segmentIndex.
	boost::json::value fixture = LoadFixture("nzb_segment_identity.json");
	const boost::json::array& vectors = fixture.at("vectors").as_array();
	BOOST_CHECK_EQUAL(vectors.size(), 33);

	unsigned int encryptedCount = 0;
	unsigned int unencryptedCount = 0;
	for (const boost::json::value& entry : vectors)
	{
		const boost::json::object& vector = entry.as_object();
		const std::string nzbXml = JsonToString(vector.at("nzb_xml"));
		if (vector.if_contains("is_encrypted") && vector.at("is_encrypted").as_bool())
		{
			encryptedCount++;
			BOOST_CHECK_MESSAGE(Contains(nzbXml, "<meta type=\"yenc_encrypted\">true</meta>"),
				("missing yenc_encrypted meta: " + JsonToString(vector.at("id"))).c_str());
			BOOST_CHECK_MESSAGE(Contains(nzbXml, "<meta type=\"password\">"),
				("missing password meta: " + JsonToString(vector.at("id"))).c_str());
			BOOST_CHECK(vector.at("expected_valid").as_bool());
		}
		else if (vector.if_contains("is_encrypted") && !vector.at("is_encrypted").as_bool())
		{
			unencryptedCount++;
			BOOST_CHECK(!Contains(nzbXml, "<meta type=\"yenc_encrypted\">"));
			BOOST_CHECK(!Contains(nzbXml, "<meta type=\"password\">"));
			BOOST_CHECK(vector.at("expected_valid").as_bool());
		}
	}
	BOOST_CHECK_EQUAL(encryptedCount, 26);
	BOOST_CHECK_EQUAL(unencryptedCount, 2);
}

BOOST_AUTO_TEST_CASE(ConformanceMalformedInputsTest)
{
	// VEC-05: every malformed vector must be rejected with zero output.
	// Authentication failures are provider-failover eligible; metadata-shape
	// failures are job-level validation errors, never provider corruption.
	boost::json::value fixture = LoadFixture("malformed_inputs.json");
	const boost::json::array& vectors = fixture.at("vectors").as_array();
	BOOST_CHECK_EQUAL(vectors.size(), 46);

	unsigned int authFailures = 0;
	unsigned int metadataFailures = 0;
	for (const boost::json::value& entry : vectors)
	{
		const boost::json::object& vector = entry.as_object();
		BOOST_CHECK(vector.at("zero_output_required").as_bool());

		const std::string stage = JsonToString(vector.at("expected_rejection_stage"));
		BOOST_CHECK(stage == "PROVIDER_FAILOVER" || stage == "METADATA_VALIDATION");

		const std::string error = JsonToString(vector.at("expected_error"));
		BOOST_CHECK(!error.empty());

		if (error == "AUTHENTICATION_FAILURE")
		{
			authFailures++;
			BOOST_CHECK_EQUAL(stage, "PROVIDER_FAILOVER");
			BOOST_CHECK(vector.at("provider_failover_permitted").as_bool());
		}
		if (stage == "METADATA_VALIDATION")
		{
			metadataFailures++;
			BOOST_CHECK(!vector.at("provider_failover_permitted").as_bool());
		}
	}
	BOOST_CHECK_EQUAL(authFailures, 4);
	BOOST_CHECK_EQUAL(metadataFailures, 4);
}

BOOST_AUTO_TEST_SUITE_END()
