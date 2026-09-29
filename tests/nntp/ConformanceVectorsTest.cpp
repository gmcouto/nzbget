/*
 *  This file is part of nzbget. See <https://nzbget.com>.
 *
 *  Copyright (C) 2026 Denis <denis@nzbget.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "nzbget.h"

#include <boost/json.hpp>
#include <boost/test/unit_test.hpp>

#include "YEncDecryptor.h"
#include "NzbFile.h"
#include "DownloadInfo.h"
#include "ArticleWriter.h"
#include "ArticleDownloader.h"
#include "Options.h"
#include "Decoder.h"
#include "Log.h"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{

std::string LoadFixtureText(const std::string& filename)
{
	namespace fs = std::filesystem;
	const std::vector<fs::path> candidates = {
		fs::path(__FILE__).parent_path() / ".." / "testdata" / "test-vectors" / filename,
		fs::current_path() / "tests" / "testdata" / "test-vectors" / filename,
		fs::current_path() / "testdata" / "test-vectors" / filename
	};
	for (const auto& path : candidates)
	{
		std::ifstream input(path, std::ios::binary);
		if (input)
		{
			std::ostringstream text;
			text << input.rdbuf();
			return text.str();
		}
	}
	BOOST_FAIL("Fixture file not found: " + filename);
	return {};
}

boost::json::object LoadFixture(const std::string& filename)
{
	return boost::json::parse(LoadFixtureText(filename)).as_object();
}

std::string JsonString(const boost::json::object& object, const char* key)
{
	return boost::json::value_to<std::string>(object.at(key));
}

uint32_t JsonUint32(const boost::json::object& object, const char* key)
{
	return boost::json::value_to<uint32_t>(object.at(key));
}

std::vector<uint8_t> HexToBin(const std::string& hex)
{
	if (hex.size() % 2 != 0)
	{
		throw std::invalid_argument("hex input must have even length");
	}
	std::vector<uint8_t> bytes;
	bytes.reserve(hex.size() / 2);
	for (size_t i = 0; i < hex.size(); i += 2)
	{
		unsigned int byteValue = 0;
		std::istringstream parser(hex.substr(i, 2));
		parser >> std::hex >> byteValue;
		if (parser.fail())
		{
			throw std::invalid_argument("hex input contains invalid characters");
		}
		bytes.push_back(static_cast<uint8_t>(byteValue));
	}
	return bytes;
}

std::string BinToHex(const uint8_t* data, size_t len)
{
	std::ostringstream result;
	for (size_t i = 0; i < len; ++i)
	{
		result << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(data[i]);
	}
	return result.str();
}

std::string BinToHex(const std::vector<uint8_t>& data)
{
	return BinToHex(data.data(), data.size());
}

void CheckZeroOutput(const boost::json::object& vector, const std::vector<uint8_t>& output)
{
	if (vector.at("zero_output_required").as_bool())
	{
		BOOST_CHECK(output.empty());
	}
}

} // anonymous namespace

BOOST_AUTO_TEST_SUITE(NNTPTest)

BOOST_AUTO_TEST_CASE(DynamicArgon2idTestVectors)
{
	const auto fixture = LoadFixture("argon2id.json");
	const auto& vectors = fixture.at("vectors").as_array();
	BOOST_REQUIRE_EQUAL(vectors.size(), 6);

	for (const auto& item : vectors)
	{
		const auto& vector = item.as_object();
		BOOST_TEST_CONTEXT(JsonString(vector, "id"))
		{
			const auto salt = HexToBin(JsonString(vector, "salt_hex"));
			YEncDecryptor decryptor(JsonString(vector, "password"));
			BOOST_REQUIRE_EQUAL(salt.size(), 16);
			BOOST_REQUIRE(decryptor.EnsureMasterKey(salt.data()));
			BOOST_CHECK_EQUAL(BinToHex(decryptor.GetCachedMasterKey()), JsonString(vector, "expected_key_hex"));
		}
	}
}

BOOST_AUTO_TEST_CASE(DynamicNonceTweakTestVectors)
{
	const auto fixture = LoadFixture("nonce_tweak.json");
	const auto& nonceVectors = fixture.at("body_nonce_vectors").as_array();
	const auto& tweakVectors = fixture.at("control_tweak_vectors").as_array();
	BOOST_REQUIRE_EQUAL(nonceVectors.size(), 8);
	BOOST_REQUIRE_EQUAL(tweakVectors.size(), 7);

	const auto bodySalt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
	const auto controlSalt = HexToBin("4b376d5839704c32715238764e34775a");

	for (const auto& item : nonceVectors)
	{
		const auto& vector = item.as_object();
		BOOST_TEST_CONTEXT(JsonString(vector, "id"))
		{
			YEncDecryptor decryptor("test123");
			BOOST_REQUIRE(decryptor.EnsureMasterKey(bodySalt.data()));
			BOOST_REQUIRE_EQUAL(BinToHex(decryptor.GetCachedMasterKey()), JsonString(vector, "key_hex"));
			uint8_t nonce[24];
			BOOST_REQUIRE(decryptor.DeriveBodyNonce(JsonUint32(vector, "segment_index"), nonce));
			BOOST_CHECK_EQUAL(BinToHex(nonce, sizeof(nonce)), JsonString(vector, "expected_nonce_hex"));
		}
	}

	for (const auto& item : tweakVectors)
	{
		const auto& vector = item.as_object();
		BOOST_TEST_CONTEXT(JsonString(vector, "id"))
		{
			YEncDecryptor decryptor("test123");
			BOOST_REQUIRE(decryptor.EnsureMasterKey(controlSalt.data()));
			BOOST_REQUIRE_EQUAL(BinToHex(decryptor.GetCachedMasterKey()), JsonString(vector, "master_key_hex"));
			uint8_t key[32];
			uint8_t tweak[8];
			BOOST_REQUIRE(decryptor.DeriveControlKeyAndTweak(
				JsonUint32(vector, "segment_index"), JsonUint32(vector, "line_index"), key, tweak));
			BOOST_CHECK_EQUAL(BinToHex(key, sizeof(key)), JsonString(vector, "enc_key_hex"));
			BOOST_CHECK_EQUAL(BinToHex(tweak, sizeof(tweak)), JsonString(vector, "expected_tweak_hex"));
		}
	}
}

BOOST_AUTO_TEST_CASE(DynamicBodyEncryptionTestVectors)
{
	const auto fixture = LoadFixture("body_encryption.json");
	const auto& vectors = fixture.at("vectors").as_array();
	BOOST_REQUIRE_EQUAL(vectors.size(), 8);

	for (const auto& item : vectors)
	{
		const auto& vector = item.as_object();
		BOOST_TEST_CONTEXT(JsonString(vector, "id"))
		{
			const auto salt = HexToBin(JsonString(vector, "salt_hex"));
			const auto ciphertext = HexToBin(JsonString(vector, "expected_ciphertext_hex"));
			const auto tag = HexToBin(JsonString(vector, "expected_tag_hex"));
			const auto expectedPlaintext = HexToBin(JsonString(vector, "plaintext_hex"));
			YEncDecryptor decryptor(JsonString(vector, "password"));
			std::vector<uint8_t> plaintext;
			const auto status = decryptor.AuthenticateAndDecrypt(
				ciphertext.data(), ciphertext.size(), salt.data(), tag.data(),
				JsonUint32(vector, "segment_index"), plaintext);
			BOOST_REQUIRE(status == YEncDecryptor::Status::Ok);
			BOOST_CHECK_EQUAL(BinToHex(plaintext), BinToHex(expectedPlaintext));
		}
	}
}

BOOST_AUTO_TEST_CASE(DynamicControlLineEncryptionTestVectors)
{
	const auto fixture = LoadFixture("control_line_encryption.json");
	const auto& vectors = fixture.at("vectors").as_array();
	BOOST_REQUIRE_EQUAL(vectors.size(), 8);

	for (const auto& item : vectors)
	{
		const auto& vector = item.as_object();
		BOOST_TEST_CONTEXT(JsonString(vector, "id"))
		{
			YEncDecryptor decryptor(JsonString(vector, "password"));
			const auto salt = HexToBin(JsonString(vector, "salt_hex"));
			const uint32_t segmentIndex = JsonUint32(vector, "segment_index");
			if (vector.contains("total_physical_lines"))
			{
				const auto& plaintextLines = vector.at("input_lines").as_array();
				const auto& wireLines = vector.at("expected_wire_lines_hex").as_array();
				BOOST_REQUIRE_EQUAL(plaintextLines.size(), JsonUint32(vector, "total_physical_lines"));
				BOOST_REQUIRE_EQUAL(wireLines.size(), plaintextLines.size());
				for (size_t i = 0; i < plaintextLines.size(); ++i)
				{
					const auto plaintext = boost::json::value_to<std::string>(plaintextLines[i]);
					const auto wire = HexToBin(boost::json::value_to<std::string>(wireLines[i]));
					if (!plaintext.starts_with("=y"))
					{
						BOOST_CHECK_EQUAL(BinToHex(wire), BinToHex(
							reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size()));
						continue;
					}
					std::vector<uint8_t> restored;
					std::vector<uint8_t> extractedSalt;
					const auto status = decryptor.DecryptControlLine(
						wire.data(), wire.size(), segmentIndex, static_cast<uint32_t>(i + 1), i == 0,
						restored, i == 0 ? &extractedSalt : nullptr);
					BOOST_REQUIRE(status == YEncDecryptor::Status::Ok);
					BOOST_CHECK_EQUAL(std::string(restored.begin(), restored.end()), plaintext);
					if (i == 0)
					{
						BOOST_CHECK_EQUAL(BinToHex(extractedSalt), BinToHex(salt));
					}
				}
			}
			else
			{
				const auto wire = HexToBin(JsonString(vector, "expected_wire_hex"));
				std::vector<uint8_t> plaintext;
				std::vector<uint8_t> extractedSalt;
				const bool isLine1 = vector.at("is_line_1").as_bool();
				if (!isLine1)
				{
					BOOST_REQUIRE_EQUAL(salt.size(), 16);
					BOOST_REQUIRE(decryptor.EnsureMasterKey(salt.data()));
				}
				const auto status = decryptor.DecryptControlLine(
					wire.data(), wire.size(), segmentIndex, JsonUint32(vector, "line_index"), isLine1,
					plaintext, isLine1 ? &extractedSalt : nullptr);
				BOOST_REQUIRE(status == YEncDecryptor::Status::Ok);
				BOOST_CHECK_EQUAL(std::string(plaintext.begin(), plaintext.end()), JsonString(vector, "plaintext_line"));
				if (isLine1)
				{
					BOOST_CHECK_EQUAL(BinToHex(extractedSalt), BinToHex(salt));
				}
			}
		}
	}
}

BOOST_AUTO_TEST_CASE(DynamicMalformedInputsTestVectors)
{
	const auto fixture = LoadFixture("malformed_inputs.json");
	const auto& vectors = fixture.at("vectors").as_array();
	const size_t testCount = 21;
	BOOST_REQUIRE(vectors.size() >= testCount);

	for (size_t i = 0; i < testCount; ++i)
	{
		const auto& item = vectors[i];
		const auto& vector = item.as_object();
		BOOST_TEST_CONTEXT(JsonString(vector, "id"))
		{
			const std::string category = JsonString(vector, "category");
			std::vector<uint8_t> output;
			if (category == "header_syntax")
			{
				YEncDecryptor::YEncryptionHeader header;
				const std::string line = JsonString(vector, "input_line");
				BOOST_CHECK(!YEncDecryptor::ParseYEncryption(line.data(), line.size(), header));
			}
			else if (category == "auth_failure")
			{
				const auto salt = HexToBin(JsonString(vector, "salt_hex"));
				const auto ciphertext = HexToBin(JsonString(
					vector, vector.contains("tampered_ciphertext_hex") ? "tampered_ciphertext_hex" : "ciphertext_hex"));
				const auto tag = HexToBin(JsonString(
					vector, vector.contains("tampered_tag_hex") ? "tampered_tag_hex" : "tag_hex"));
				YEncDecryptor decryptor(JsonString(vector, "password"));
				const auto status = decryptor.AuthenticateAndDecrypt(
					ciphertext.data(), ciphertext.size(), salt.data(), tag.data(),
					JsonUint32(vector, "segment_index"), output);
				BOOST_CHECK(status == YEncDecryptor::Status::AuthFailed);
				CheckZeroOutput(vector, output);
			}
			else
			{
				const std::string id = JsonString(vector, "id");
				YEncDecryptor decryptor(vector.contains("wrong_password") ? JsonString(vector, "wrong_password") : "test123");
				std::vector<uint8_t> wire;
				bool isLine1 = true;
				if (vector.contains("tampered_salt_hex"))
				{
					wire = HexToBin(JsonString(vector, "tampered_salt_hex"));
					wire.insert(wire.end(), {'=', 'y'});
				}
				else if (vector.contains("line1_hex"))
				{
					wire = HexToBin(JsonString(vector, "line1_hex"));
				}
				else if (vector.contains("line_hex"))
				{
					wire = HexToBin(JsonString(vector, "line_hex"));
					isLine1 = false;
				}
				else
				{
					wire = HexToBin("4b376d5839704c32715238764e34775a3ff69054da2b2309591e740e5b9fd79015f610d42f01bd203e5f55dadc39fc760407e845201f");
				}
				const auto status = decryptor.DecryptControlLine(
					wire.data(), wire.size(), 1, isLine1 ? 1 : 2, isLine1, output);
				if (id == "control-syntax-06-wrong-password")
				{
					const bool restoredControlLine = status == YEncDecryptor::Status::Ok &&
						output.size() >= 2 && output[0] == '=' && output[1] == 'y';
					BOOST_CHECK(!restoredControlLine);
					if (restoredControlLine)
					{
						output.clear();
					}
				}
				else
				{
					BOOST_CHECK(status != YEncDecryptor::Status::Ok);
					CheckZeroOutput(vector, output);
				}
			}
		}
	}
}

BOOST_AUTO_TEST_CASE(NzbSegmentIdentityTestVectors)
{
	Options::CmdOptList cmdOpts;
	std::string destOpt = "DestDir=" + std::filesystem::temp_directory_path().string();
	std::string interOpt = "InterDir=";
	cmdOpts.push_back(destOpt.c_str());
	cmdOpts.push_back(interOpt.c_str());
	Options options(&cmdOpts, nullptr);
	Options* oldOptions = g_Options;
	g_Options = &options;

	const auto fixture = LoadFixture("nzb_segment_identity.json");
	const auto& vectors = fixture.at("vectors").as_array();
	BOOST_REQUIRE_EQUAL(vectors.size(), 33U);

	for (const auto& item : vectors)
	{
		const auto& vector = item.as_object();
		const std::string id = JsonString(vector, "id");
		const std::string category = JsonString(vector, "category");
		BOOST_TEST_CONTEXT(id)
		{
			const std::filesystem::path tempNzb = std::filesystem::temp_directory_path() / (id + ".nzb");
			{
				std::ofstream output(tempNzb, std::ios::binary);
				output << JsonString(vector, "nzb_xml");
			}

			NzbFile nzbFile(tempNzb.string().c_str(), "");
			bool parsed = nzbFile.Parse();
			std::unique_ptr<NzbInfo> nzbInfo = nzbFile.DetachNzbInfo();
			std::filesystem::remove(tempNzb);

			if (category == "valid_identity")
			{
				BOOST_REQUIRE(parsed);
				BOOST_REQUIRE(nzbInfo);
				BOOST_CHECK(nzbInfo->IsYEncEncrypted());

				std::unordered_map<std::string, uint32_t> actual;
				for (const auto& fileInfo : *nzbInfo->GetFileList())
				{
					for (const auto& article : *fileInfo->GetArticles())
					{
						BOOST_REQUIRE(article->HasSegmentIndex());
						std::string mid = article->GetMessageId();
						if (mid.size() >= 2 && mid.front() == '<' && mid.back() == '>')
						{
							mid = mid.substr(1, mid.size() - 2);
						}
						actual[mid] = article->GetSegmentIndex().value();
					}
				}

				for (const auto& expectedItem : vector.at("expected_segments").as_array())
				{
					const auto& expected = expectedItem.as_object();
					const std::string mid = JsonString(expected, "message_id");
					BOOST_REQUIRE(actual.find(mid) != actual.end());
					BOOST_CHECK_EQUAL(actual[mid], JsonUint32(expected, "segment_index"));
				}
			}
			else if (category == "invalid_identity")
			{
				if (id == "nzb-invalid-17-missing-index-encrypted")
				{
					// Password-only without explicit encryption provenance is an archive password release.
					BOOST_REQUIRE(parsed);
					BOOST_REQUIRE(nzbInfo);
					BOOST_CHECK(!nzbInfo->IsYEncEncrypted());
				}
				else
				{
					BOOST_CHECK(!parsed);
					BOOST_REQUIRE(nzbInfo);
					const std::string expectedError = JsonString(vector, "expected_error");
					bool found = false;
					for (Message& message : nzbInfo->GuardCachedMessages())
					{
						if (std::string(message.GetText()).find(expectedError) != std::string::npos)
						{
							found = true;
							break;
						}
					}
					BOOST_CHECK(found);
				}
			}
			else if (category == "unencrypted_compatibility")
			{
				BOOST_REQUIRE(parsed);
				BOOST_REQUIRE(nzbInfo);
				BOOST_CHECK(!nzbInfo->IsYEncEncrypted());
				for (const auto& fileInfo : *nzbInfo->GetFileList())
				{
					for (const auto& article : *fileInfo->GetArticles())
					{
						BOOST_CHECK(!article->HasSegmentIndex());
					}
				}
			}
			else if (category == "index_tampering")
			{
				BOOST_REQUIRE(parsed);
				BOOST_REQUIRE(nzbInfo);
				BOOST_CHECK(nzbInfo->IsYEncEncrypted());

				YEncDecryptor decryptor(JsonString(vector, "password"));
				const auto salt = HexToBin(JsonString(vector, "salt_hex"));
				std::vector<uint8_t> plaintext;

				if (id == "nzb-tamper-01-index-mismatch-zero-output")
				{
					const auto ciphertext = HexToBin(JsonString(vector, "ciphertext_hex"));
					const auto tag = HexToBin(JsonString(vector, "tag_hex"));
					const auto status = decryptor.AuthenticateAndDecrypt(
						ciphertext.data(), ciphertext.size(), salt.data(), tag.data(),
						JsonUint32(vector, "tampered_segment_index"), plaintext);
					BOOST_CHECK(status == YEncDecryptor::Status::AuthFailed);
					BOOST_CHECK(plaintext.empty());
				}
				else
				{
					for (const auto& segmentItem : vector.at("tampered_segments").as_array())
					{
						const auto& segment = segmentItem.as_object();
						const auto ciphertext = HexToBin(JsonString(segment, "ciphertext_hex"));
						const auto tag = HexToBin(JsonString(segment, "tag_hex"));
						plaintext.clear();
						YEncDecryptor segmentDecryptor(JsonString(vector, "password"));
						const auto status = segmentDecryptor.AuthenticateAndDecrypt(
							ciphertext.data(), ciphertext.size(), salt.data(), tag.data(),
							JsonUint32(segment, "tampered_segment_index"), plaintext);
						BOOST_CHECK(status == YEncDecryptor::Status::AuthFailed);
						BOOST_CHECK(plaintext.empty());
					}
				}
			}
		}
	}

	g_Options = oldOptions;
}

BOOST_AUTO_TEST_CASE(ProviderFailoverOnAuthFailureTest)
{
	YEncDecryptor decryptor("test123");
	const auto salt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
	const auto ciphertext = HexToBin("710d1cad23ac7a8b120cee7a3ae792ffd31b1ae3e45f4ee6cb4b53288255b474a89845bd8daf7976f9dd2ce836a0f4d675");
	const auto tag = HexToBin("244b59a79fd448b7d2fa6fdd378e3153");
	std::vector<uint8_t> plaintext;

	// Provider 1 uses tampered NZB index 2: auth failure and zero output.
	auto status = decryptor.AuthenticateAndDecrypt(
		ciphertext.data(), ciphertext.size(), salt.data(), tag.data(), 2, plaintext);
	BOOST_CHECK(status == YEncDecryptor::Status::AuthFailed);
	BOOST_CHECK(plaintext.empty());
	ArticleDownloader::EStatus firstProvider = status == YEncDecryptor::Status::AuthFailed ?
		ArticleDownloader::adFailed : ArticleDownloader::adFinished;
	BOOST_CHECK(firstProvider == ArticleDownloader::adFailed);

	// Provider 2 uses authoritative index 1: authenticated plaintext succeeds.
	status = decryptor.AuthenticateAndDecrypt(
		ciphertext.data(), ciphertext.size(), salt.data(), tag.data(), 1, plaintext);
	BOOST_CHECK(status == YEncDecryptor::Status::Ok);
	BOOST_CHECK(!plaintext.empty());
	ArticleDownloader::EStatus secondProvider = status == YEncDecryptor::Status::Ok ?
		ArticleDownloader::adFinished : ArticleDownloader::adFailed;
	BOOST_CHECK(secondProvider == ArticleDownloader::adFinished);
}

BOOST_AUTO_TEST_SUITE_END()
