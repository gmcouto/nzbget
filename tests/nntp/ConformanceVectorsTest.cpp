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
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "nzbget.h"

#include <boost/json.hpp>
#include <boost/test/unit_test.hpp>

#include "YEncDecryptor.h"
#include "Decoder.h"

#include <filesystem>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace
{

std::string LoadFixtureText(const std::string& filename)
{
	namespace fs = std::filesystem;
	const std::vector<fs::path> candidates = {
		fs::path(__FILE__).parent_path() / ".." / "testdata" / "test-vectors" / filename,
		fs::current_path() / "testdata" / "test-vectors" / filename,
		fs::current_path() / "nntp" / "testdata" / "test-vectors" / filename,
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

std::vector<uint8_t> HexToBytes(const std::string& hex)
{
	std::vector<uint8_t> bytes;
	bytes.reserve(hex.size() / 2);
	for (size_t i = 0; i + 1 < hex.size(); i += 2)
	{
		unsigned int byteVal = 0;
		std::stringstream ss;
		ss << std::hex << hex.substr(i, 2);
		ss >> byteVal;
		bytes.push_back(static_cast<uint8_t>(byteVal));
	}
	return bytes;
}

std::string BytesToHex(const uint8_t* data, size_t len)
{
	static const char hexChars[] = "0123456789abcdef";
	std::string hex;
	hex.reserve(len * 2);
	for (size_t i = 0; i < len; ++i)
	{
		hex.push_back(hexChars[(data[i] >> 4) & 0x0F]);
		hex.push_back(hexChars[data[i] & 0x0F]);
	}
	return hex;
}

} // anonymous namespace

BOOST_AUTO_TEST_SUITE(NNTPTest)

// VEC-01: Argon2id Key Derivation
BOOST_AUTO_TEST_CASE(ConformanceArgon2idVectorsTest)
{
	boost::json::value fixture = LoadFixture("argon2id.json");
	const boost::json::array& vectors = fixture.at("vectors").as_array();
	BOOST_CHECK_EQUAL(vectors.size(), 6);

	for (const auto& entry : vectors)
	{
		const auto& vec = entry.as_object();
		std::string id = vec.at("id").as_string().c_str();
		std::string password = vec.at("password").as_string().c_str();
		std::string saltHex = vec.at("salt_hex").as_string().c_str();
		std::string expectedKeyHex = vec.at("expected_key_hex").as_string().c_str();

		std::vector<uint8_t> salt = HexToBytes(saltHex);
		BOOST_REQUIRE_EQUAL(salt.size(), 16);

		YEncDecryptor decryptor(password);
		bool ok = decryptor.EnsureMasterKey(salt.data());
		BOOST_CHECK_MESSAGE(ok, ("EnsureMasterKey failed for " + id).c_str());

		const std::vector<uint8_t>& key = decryptor.GetCachedMasterKey();
		std::string actualKeyHex = BytesToHex(key.data(), key.size());
		BOOST_CHECK_EQUAL(actualKeyHex, expectedKeyHex);
	}
}

// VEC-02: Nonce and Tweak Derivation
BOOST_AUTO_TEST_CASE(ConformanceNonceTweakVectorsTest)
{
	boost::json::value fixture = LoadFixture("nonce_tweak.json");

	const boost::json::array& bodyNonceVectors = fixture.at("body_nonce_vectors").as_array();
	for (const auto& entry : bodyNonceVectors)
	{
		const auto& vec = entry.as_object();
		std::string id = vec.at("id").as_string().c_str();
		std::string masterKeyHex = vec.at("key_hex").as_string().c_str();
		std::vector<uint8_t> masterKey = HexToBytes(masterKeyHex);
		BOOST_REQUIRE_EQUAL(masterKey.size(), 32);

		uint32_t segmentIndex = static_cast<uint32_t>(vec.at("segment_index").to_number<uint32_t>());
		std::string expectedNonceHex = vec.at("expected_nonce_hex").as_string().c_str();

		YEncDecryptor decryptor;
		decryptor.SetMasterKeyForTesting(masterKey.data());

		uint8_t nonce[24];
		bool ok = decryptor.DeriveBodyNonce(segmentIndex, nonce);
		BOOST_CHECK_MESSAGE(ok, ("DeriveBodyNonce failed for " + id).c_str());
		std::string actualNonceHex = BytesToHex(nonce, 24);
		BOOST_CHECK_EQUAL(actualNonceHex, expectedNonceHex);
	}

	const boost::json::array& controlTweakVectors = fixture.at("control_tweak_vectors").as_array();
	for (const auto& entry : controlTweakVectors)
	{
		const auto& vec = entry.as_object();
		std::string id = vec.at("id").as_string().c_str();
		std::string masterKeyHex = vec.at("master_key_hex").as_string().c_str();
		std::vector<uint8_t> masterKey = HexToBytes(masterKeyHex);
		BOOST_REQUIRE_EQUAL(masterKey.size(), 32);

		uint32_t segmentIndex = static_cast<uint32_t>(vec.at("segment_index").to_number<uint32_t>());
		uint32_t lineIndex = static_cast<uint32_t>(vec.at("line_index").to_number<uint32_t>());
		std::string expectedTweakHex = vec.at("expected_tweak_hex").as_string().c_str();

		YEncDecryptor decryptor;
		decryptor.SetMasterKeyForTesting(masterKey.data());

		uint8_t encKey[32];
		uint8_t tweak[8];
		bool ok = decryptor.DeriveControlKeyAndTweak(segmentIndex, lineIndex, encKey, tweak);
		BOOST_CHECK_MESSAGE(ok, ("DeriveControlKeyAndTweak failed for " + id).c_str());
		std::string actualTweakHex = BytesToHex(tweak, 8);
		BOOST_CHECK_EQUAL(actualTweakHex, expectedTweakHex);

		if (vec.if_contains("enc_key_hex"))
		{
			std::string expectedKeyHex = vec.at("enc_key_hex").as_string().c_str();
			std::string actualKeyHex = BytesToHex(encKey, 32);
			BOOST_CHECK_EQUAL(actualKeyHex, expectedKeyHex);
		}
	}
}

// VEC-03: Body Encryption (XChaCha20-Poly1305)
BOOST_AUTO_TEST_CASE(ConformanceBodyEncryptionVectorsTest)
{
	boost::json::value fixture = LoadFixture("body_encryption.json");
	const boost::json::array& vectors = fixture.at("vectors").as_array();
	BOOST_CHECK_GE(vectors.size(), 8);

	for (const auto& entry : vectors)
	{
		const auto& vec = entry.as_object();
		std::string id = vec.at("id").as_string().c_str();
		std::string password = vec.at("password").as_string().c_str();
		std::string saltHex = vec.at("salt_hex").as_string().c_str();
		uint32_t segmentIndex = static_cast<uint32_t>(vec.at("segment_index").to_number<uint32_t>());
		std::string ptHex = vec.at("plaintext_hex").as_string().c_str();
		std::string ctHex = vec.at("expected_ciphertext_hex").as_string().c_str();
		std::string tagHex = vec.at("expected_tag_hex").as_string().c_str();
		std::string yencLine = vec.at("expected_yencryption_line").as_string().c_str();

		std::vector<uint8_t> salt = HexToBytes(saltHex);
		std::vector<uint8_t> ct = HexToBytes(ctHex);
		std::vector<uint8_t> tag = HexToBytes(tagHex);
		std::vector<uint8_t> expectedPlaintext = HexToBytes(ptHex);

		YEncDecryptor decryptor(password);
		std::vector<uint8_t> outPlaintext;

		YEncDecryptor::Status status = decryptor.AuthenticateAndDecrypt(
			ct.data(), ct.size(), salt.data(), tag.data(), segmentIndex, outPlaintext
		);
		BOOST_CHECK_MESSAGE(status == YEncDecryptor::Status::Ok, ("AuthenticateAndDecrypt failed for " + id).c_str());
		BOOST_CHECK_EQUAL_COLLECTIONS(outPlaintext.begin(), outPlaintext.end(), expectedPlaintext.begin(), expectedPlaintext.end());

		// Test ParseYEncryption on expected_yencryption_line
		YEncDecryptor::YEncryptionHeader header;
		bool parsed = YEncDecryptor::ParseYEncryption(yencLine.c_str(), header);
		BOOST_CHECK_MESSAGE(parsed, ("ParseYEncryption failed for " + id).c_str());
		BOOST_CHECK_EQUAL(header.segmentIndex, segmentIndex);
		BOOST_CHECK_EQUAL(header.saltHex, saltHex);
		BOOST_CHECK_EQUAL(header.tagHex, tagHex);

		// Zero-Output Guarantee: tag tampering
		std::vector<uint8_t> corruptTag = tag;
		corruptTag[0] ^= 0x01;
		std::vector<uint8_t> tamperedPlaintext;
		status = decryptor.AuthenticateAndDecrypt(
			ct.data(), ct.size(), salt.data(), corruptTag.data(), segmentIndex, tamperedPlaintext
		);
		BOOST_CHECK_EQUAL(static_cast<int>(status), static_cast<int>(YEncDecryptor::Status::AuthFailed));
		BOOST_CHECK(tamperedPlaintext.empty());
	}
}

// VEC-04: Control Line Encryption (Radix-253 FF1)
BOOST_AUTO_TEST_CASE(ConformanceControlLineEncryptionVectorsTest)
{
	boost::json::value fixture = LoadFixture("control_line_encryption.json");
	const boost::json::array& vectors = fixture.at("vectors").as_array();
	BOOST_CHECK_EQUAL(vectors.size(), 8);

	for (const auto& entry : vectors)
	{
		const auto& vec = entry.as_object();
		std::string id = vec.at("id").as_string().c_str();
		std::string password = vec.at("password").as_string().c_str();
		std::string saltHex = vec.at("salt_hex").as_string().c_str();
		uint32_t segmentIndex = static_cast<uint32_t>(vec.at("segment_index").to_number<uint32_t>());

		std::vector<uint8_t> salt = HexToBytes(saltHex);
		YEncDecryptor decryptor(password);
		BOOST_REQUIRE(decryptor.EnsureMasterKey(salt.data()));

		if (vec.if_contains("input_lines"))
		{
			const auto& inputLines = vec.at("input_lines").as_array();
			const auto& expectedWireLines = vec.at("expected_wire_lines_hex").as_array();
			BOOST_REQUIRE_EQUAL(inputLines.size(), expectedWireLines.size());

			for (size_t i = 0; i < inputLines.size(); ++i)
			{
				std::string plainLine = inputLines[i].as_string().c_str();
				std::string wireHex = expectedWireLines[i].as_string().c_str();
				std::vector<uint8_t> wireBytes = HexToBytes(wireHex);
				bool isLine1 = (i == 0);
				uint32_t lineIndex = static_cast<uint32_t>(i + 1);

				if (plainLine.rfind("=y", 0) == 0)
				{
					// Encrypted control line
					std::vector<uint8_t> restoredPlain;
					std::vector<uint8_t> outSalt;
					uint32_t outSegmentIndex = 0;
					YEncDecryptor::Status decStatus = decryptor.DecryptControlLine(
						wireBytes.data(), wireBytes.size(),
						segmentIndex, lineIndex, isLine1, restoredPlain,
						isLine1 ? &outSalt : nullptr, isLine1 ? &outSegmentIndex : nullptr
					);
					BOOST_CHECK_MESSAGE(decStatus == YEncDecryptor::Status::Ok, ("DecryptControlLine failed for " + id + " line " + std::to_string(lineIndex)).c_str());
					if (isLine1)
					{
						BOOST_CHECK_EQUAL(BytesToHex(outSalt.data(), outSalt.size()), saltHex);
						BOOST_CHECK_EQUAL(outSegmentIndex, segmentIndex);
					}
					std::string restoredStr(reinterpret_cast<const char*>(restoredPlain.data()), restoredPlain.size());
					BOOST_CHECK_EQUAL(restoredStr, plainLine);

					// Test EncryptControlLine roundtrip to wireHex
					std::vector<uint8_t> outWire;
					YEncDecryptor::Status encStatus = decryptor.EncryptControlLine(
						reinterpret_cast<const uint8_t*>(plainLine.data()), plainLine.size(),
						segmentIndex, lineIndex, isLine1, salt.data(), outWire
					);
					BOOST_CHECK_MESSAGE(encStatus == YEncDecryptor::Status::Ok, ("EncryptControlLine failed for " + id + " line " + std::to_string(lineIndex)).c_str());
					BOOST_CHECK_EQUAL(BytesToHex(outWire.data(), outWire.size()), wireHex);
				}
				else
				{
					// Data line: untouched byte-for-byte per Control Lines Encryption Standard
					std::string wireStr(reinterpret_cast<const char*>(wireBytes.data()), wireBytes.size());
					BOOST_CHECK_EQUAL(wireStr, plainLine);
				}
			}
		}
		else if (vec.if_contains("plaintext_line"))
		{
			std::string plainLine = vec.at("plaintext_line").as_string().c_str();
			std::string wireHex = vec.at("expected_wire_hex").as_string().c_str();
			std::vector<uint8_t> wireBytes = HexToBytes(wireHex);
			uint32_t lineIndex = static_cast<uint32_t>(vec.at("line_index").to_number<uint32_t>());
			bool isLine1 = vec.if_contains("is_line_1") ? vec.at("is_line_1").as_bool() : false;

			// Test DecryptControlLine
			std::vector<uint8_t> restoredPlain;
			std::vector<uint8_t> outSalt;
			uint32_t outSegmentIndex = 0;
			YEncDecryptor::Status decStatus = decryptor.DecryptControlLine(
				wireBytes.data(), wireBytes.size(),
				segmentIndex, lineIndex, isLine1, restoredPlain,
				isLine1 ? &outSalt : nullptr, isLine1 ? &outSegmentIndex : nullptr
			);
			BOOST_CHECK_MESSAGE(decStatus == YEncDecryptor::Status::Ok, ("DecryptControlLine failed for " + id).c_str());
			if (isLine1)
			{
				BOOST_CHECK_EQUAL(BytesToHex(outSalt.data(), outSalt.size()), saltHex);
				BOOST_CHECK_EQUAL(outSegmentIndex, segmentIndex);
			}
			std::string restoredStr(reinterpret_cast<const char*>(restoredPlain.data()), restoredPlain.size());
			BOOST_CHECK_EQUAL(restoredStr, plainLine);

			// Test EncryptControlLine roundtrip to wireHex
			std::vector<uint8_t> outWire;
			YEncDecryptor::Status encStatus = decryptor.EncryptControlLine(
				reinterpret_cast<const uint8_t*>(plainLine.data()), plainLine.size(),
				segmentIndex, lineIndex, isLine1, salt.data(), outWire
			);
			BOOST_CHECK_MESSAGE(encStatus == YEncDecryptor::Status::Ok, ("EncryptControlLine failed for " + id).c_str());
			BOOST_CHECK_EQUAL(BytesToHex(outWire.data(), outWire.size()), wireHex);
		}
	}
}

// VEC-05: Malformed Inputs and Authentication Failures
BOOST_AUTO_TEST_CASE(ConformanceMalformedInputsAuthFailuresTest)
{
	boost::json::value fixture = LoadFixture("malformed_inputs.json");
	const boost::json::array& vectors = fixture.at("vectors").as_array();
	BOOST_CHECK_EQUAL(vectors.size(), 46);

	for (const auto& entry : vectors)
	{
		const auto& vec = entry.as_object();
		std::string id = vec.at("id").as_string().c_str();
		std::string category = vec.at("category").as_string().c_str();
		std::string expectedError = vec.at("expected_error").as_string().c_str();
		bool zeroOutputRequired = vec.at("zero_output_required").as_bool();
		std::string stage = vec.at("expected_rejection_stage").as_string().c_str();

		// Every vector requires zero output
		BOOST_CHECK(zeroOutputRequired);
		BOOST_CHECK(stage == "PROVIDER_FAILOVER" || stage == "METADATA_VALIDATION");

		if (category == "header_syntax" && vec.if_contains("input_line"))
		{
			std::string inputLine = vec.at("input_line").as_string().c_str();
			YEncDecryptor::YEncryptionHeader header;
			bool parsed = YEncDecryptor::ParseYEncryption(inputLine.c_str(), header);
			BOOST_CHECK_MESSAGE(!parsed, ("Expected header parse failure for " + id).c_str());
		}
		else if (category == "tag_verification" && vec.if_contains("expected_ciphertext_hex") && vec.if_contains("expected_tag_hex"))
		{
			std::string password = vec.if_contains("password") ? vec.at("password").as_string().c_str() : "test123";
			std::string saltHex = vec.if_contains("salt_hex") ? vec.at("salt_hex").as_string().c_str() : "1a2b3c4d5e6f7890abcdef1234567890";
			uint32_t segmentIndex = vec.if_contains("segment_index") ? static_cast<uint32_t>(vec.at("segment_index").to_number<uint32_t>()) : 1;
			std::vector<uint8_t> ct = HexToBytes(vec.at("expected_ciphertext_hex").as_string().c_str());
			std::vector<uint8_t> tag = HexToBytes(vec.at("expected_tag_hex").as_string().c_str());
			std::vector<uint8_t> salt = HexToBytes(saltHex);

			YEncDecryptor decryptor(password);
			std::vector<uint8_t> outPlaintext;
			YEncDecryptor::Status status = decryptor.AuthenticateAndDecrypt(
				ct.data(), ct.size(), salt.data(), tag.data(), segmentIndex, outPlaintext
			);
			BOOST_CHECK_MESSAGE(status == YEncDecryptor::Status::AuthFailed, ("Expected AuthFailed for " + id).c_str());
			BOOST_CHECK_MESSAGE(outPlaintext.empty(), ("Expected Zero-Output for " + id).c_str());
		}
		else if (category == "forbidden_index_byte")
		{
			// Wire bootstrap with CR or LF in uint32_be(segmentIndex) must fail bootstrap extraction
			uint8_t bootstrap[22] = {0};
			memset(bootstrap, 0x41, 16); // non-zero salt
			bootstrap[16] = 0x00;
			bootstrap[17] = 0x0A; // forbidden byte
			bootstrap[18] = 0x00;
			bootstrap[19] = 0x01;
			bootstrap[20] = 0x42;
			bootstrap[21] = 0x43;

			YEncDecryptor decryptor("test123");
			std::vector<uint8_t> outPlaintext;
			YEncDecryptor::Status status = decryptor.DecryptControlLine(
				bootstrap, 22, 1, 1, true, outPlaintext
			);
			BOOST_CHECK(status == YEncDecryptor::Status::Error);
			BOOST_CHECK(outPlaintext.empty());
		}
		else if (category == "dual_bootstrap")
		{
			// Mismatched salt or segmentIndex between Line 1 and header must fail closed
			YEncDecryptor decryptor("test123");
			std::string dummyWire = "wire";
			std::string outClean;
			std::vector<uint8_t> outSalt;
			bool restored = decryptor.RestoreControlLines(dummyWire.c_str(), dummyWire.size(), 1, outClean, outSalt);
			BOOST_CHECK(!restored);
			BOOST_CHECK(outClean.empty());
		}
	}
}

BOOST_AUTO_TEST_SUITE_END()
