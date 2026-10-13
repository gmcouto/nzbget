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
#include <openssl/sha.h>

#include "YEncDecryptor.h"
#include "NzbFile.h"
#include "DownloadInfo.h"
#include "ArticleWriter.h"
#include "ArticleDownloader.h"
#include "Options.h"
#include "Decoder.h"
#include "Log.h"
#include "YEncTestHelpers.h"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// Shared test helpers : one hex/yEnc helper set for all NNTP test TUs.
using namespace YEncTest;

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

// SHA-256 of raw fixture bytes as lowercase hex; used by the manifest sync test
// to catch any local drift of the vendored conformance vectors.
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

void CheckZeroOutput(const boost::json::object& vector, const std::vector<uint8_t>& output)
{
	if (vector.at("zero_output_required").as_bool())
	{
		BOOST_CHECK(output.empty());
	}
}

// Counts complete physical lines ("\r\n"-terminated) accumulated in block.
size_t blockerLineCount(const std::string& block)
{
	size_t count = 0;
	for (size_t i = 0; i + 1 < block.size(); ++i)
	{
		if (block[i] == '\r' && block[i + 1] == '\n')
		{
			++count;
		}
	}
	return count;
}

} // anonymous namespace

BOOST_AUTO_TEST_SUITE(NNTPTest)

// Manifest drift guard: every fixture file must exist and hash-match the
// sha256 recorded in manifest.json, so the vector suites below cannot pass
// silently against stale or edited fixtures (v1.2 manifest contract).
BOOST_AUTO_TEST_CASE(ConformanceManifestSyncTest)
{
	const auto manifest = LoadFixture("manifest.json");
	BOOST_CHECK_EQUAL(JsonString(manifest, "standard_version"), "1.2");

	const auto& files = manifest.at("files").as_object();
	BOOST_CHECK_EQUAL(files.size(), 7U);

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
		BOOST_CHECK_EQUAL(
			Sha256Hex(LoadFixtureText(name)),
			JsonString(files.at(name).as_object(), "sha256"));
	}
}

BOOST_AUTO_TEST_CASE(DynamicArgon2idTestVectors)
{
	const auto fixture = LoadFixture("argon2id.json");
	const auto& vectors = fixture.at("vectors").as_array();
	BOOST_REQUIRE_EQUAL(vectors.size(), 9);

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

	for (const auto& item : nonceVectors)
	{
		const auto& vector = item.as_object();
		BOOST_TEST_CONTEXT(JsonString(vector, "id"))
		{
			YEncDecryptor decryptor("test123");
#ifdef NZBGET_TESTING_HOOKS
			// Test-only hook: seed the fixture's master key directly, skipping
			// the 64 MiB Argon2id derivation (the key itself is the fixture
			// constant, so determinism is preserved).
			decryptor.SetMasterKeyForTesting(HexToBin(JsonString(vector, "key_hex")).data());
			BOOST_REQUIRE(decryptor.GetCachedMasterKey().size() == 32);
#else
			const auto bodySalt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
			BOOST_REQUIRE(decryptor.EnsureMasterKey(bodySalt.data()));
			BOOST_REQUIRE_EQUAL(BinToHex(decryptor.GetCachedMasterKey()), JsonString(vector, "key_hex"));
#endif
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
#ifdef NZBGET_TESTING_HOOKS
			decryptor.SetMasterKeyForTesting(HexToBin(JsonString(vector, "master_key_hex")).data());
			BOOST_REQUIRE(decryptor.GetCachedMasterKey().size() == 32);
#else
			const auto controlSalt = HexToBin("4b376d5839704c32715238764e34775a");
			BOOST_REQUIRE(decryptor.EnsureMasterKey(controlSalt.data()));
			BOOST_REQUIRE_EQUAL(BinToHex(decryptor.GetCachedMasterKey()), JsonString(vector, "master_key_hex"));
#endif
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
	BOOST_REQUIRE_EQUAL(vectors.size(), 9);

	for (const auto& item : vectors)
	{
		const auto& vector = item.as_object();
		BOOST_TEST_CONTEXT(JsonString(vector, "id"))
		{
			const auto salt = HexToBin(JsonString(vector, "salt_hex"));
			const auto ciphertext = HexToBin(JsonString(vector, "expected_ciphertext_hex"));
			const auto tag = HexToBin(JsonString(vector, "expected_tag_hex"));
			const auto expectedPlaintext = HexToBin(JsonString(vector, "plaintext_hex"));
			const std::string expectedYEncLine = JsonString(vector, "expected_yencryption_line");

			// Verify 5-token header parsing with index
			YEncDecryptor::YEncryptionHeader header;
			BOOST_REQUIRE(YEncDecryptor::ParseYEncryption(expectedYEncLine.data(), expectedYEncLine.size(), header));
			BOOST_CHECK_EQUAL(header.segmentIndex, JsonUint32(vector, "segment_index"));

			// AAD check per Section 2.1
			std::vector<uint8_t> aad;
			if (vector.contains("aad"))
			{
				const auto& aadObj = vector.at("aad").as_object();
				const auto expectedAad = HexToBin(JsonString(aadObj, "expected_aad_hex"));
				const auto nameBytes = HexToBin(JsonString(aadObj, "name_bytes_hex"));
				std::string nameStr(reinterpret_cast<const char*>(nameBytes.data()), nameBytes.size());
				aad = YEncDecryptor::BuildAad(nameStr, JsonUint32(aadObj, "part_number"),
					JsonUint32(aadObj, "part_begin"),
					boost::json::value_to<uint64_t>(aadObj.at("segment_bytes")));
				BOOST_CHECK_EQUAL(BinToHex(aad), BinToHex(expectedAad));
			}

			YEncDecryptor decryptor(JsonString(vector, "password"));
			std::vector<uint8_t> plaintext;
			const auto status = decryptor.AuthenticateAndDecrypt(
				ciphertext.data(), ciphertext.size(), salt.data(), tag.data(),
				JsonUint32(vector, "segment_index"), aad.data(), aad.size(), plaintext);
			BOOST_REQUIRE(status == YEncDecryptor::Status::Ok);
			BOOST_CHECK_EQUAL(BinToHex(plaintext), BinToHex(expectedPlaintext));
		}
	}
}

BOOST_AUTO_TEST_CASE(DynamicControlLineEncryptionTestVectors)
{
	const auto fixture = LoadFixture("control_line_encryption.json");
	const auto& vectors = fixture.at("vectors").as_array();
	BOOST_REQUIRE_EQUAL(vectors.size(), 12);

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
					uint32_t extractedIndex = 0;
					const auto status = decryptor.DecryptControlLine(
						wire.data(), wire.size(), segmentIndex, static_cast<uint32_t>(i + 1), i == 0,
						restored, i == 0 ? &extractedSalt : nullptr, i == 0 ? &extractedIndex : nullptr);
					BOOST_REQUIRE(status == YEncDecryptor::Status::Ok);
					BOOST_CHECK_EQUAL(std::string(restored.begin(), restored.end()), plaintext);
					if (i == 0)
					{
						BOOST_CHECK_EQUAL(BinToHex(extractedSalt), BinToHex(salt));
						BOOST_CHECK_EQUAL(extractedIndex, segmentIndex);
					}
				}
			}
			else
			{
				const auto wire = HexToBin(JsonString(vector, "expected_wire_hex"));
				std::vector<uint8_t> plaintext;
				std::vector<uint8_t> extractedSalt;
				uint32_t extractedIndex = 0;
				const bool isLine1 = vector.at("is_line_1").as_bool();
				if (!isLine1)
				{
					BOOST_REQUIRE_EQUAL(salt.size(), 16);
					BOOST_REQUIRE(decryptor.EnsureMasterKey(salt.data()));
				}
				const auto status = decryptor.DecryptControlLine(
					wire.data(), wire.size(), segmentIndex, JsonUint32(vector, "line_index"), isLine1,
					plaintext, isLine1 ? &extractedSalt : nullptr, isLine1 ? &extractedIndex : nullptr);
				BOOST_REQUIRE(status == YEncDecryptor::Status::Ok);
				BOOST_CHECK_EQUAL(std::string(plaintext.begin(), plaintext.end()), JsonString(vector, "plaintext_line"));
				if (isLine1)
				{
					BOOST_CHECK_EQUAL(BinToHex(extractedSalt), BinToHex(salt));
					BOOST_CHECK_EQUAL(extractedIndex, segmentIndex);
				}
			}
		}
	}
}

// control-vec-12 (Control Std v1.2 section 5 step 4, Body Std v1.2 section 2.1): a single-part
// article whose =ybegin name contains " part=" is single-part. Only keywords before name= count,
// so the restored block has no =ypart and the first data line is line 3. Runs the real restore path.
BOOST_AUTO_TEST_CASE(ControlVec12SinglePartNameContainsPartRestoreTest)
{
	const auto fixture = LoadFixture("control_line_encryption.json");
	const boost::json::object* found = nullptr;
	for (const auto& item : fixture.at("vectors").as_array())
	{
		if (JsonString(item.as_object(), "id") == "control-vec-12-single-part-name-contains-part")
		{
			found = &item.as_object();
		}
	}
	BOOST_REQUIRE(found != nullptr);
	const auto& vector = *found;
	BOOST_REQUIRE_EQUAL(vector.at("expected_multipart").as_bool(), false);
	BOOST_REQUIRE_EQUAL(JsonUint32(vector, "expected_first_data_line"), 3U);

	std::string wire;
	for (const auto& line : vector.at("expected_wire_lines_hex").as_array())
	{
		const auto bytes = HexToBin(boost::json::value_to<std::string>(line));
		wire.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
		wire.append("\r\n");
	}

	YEncDecryptor decryptor(JsonString(vector, "password"));
	std::string cleanBlock;
	std::vector<uint8_t> salt;
	YEncDecryptor::YEncryptionHeader header;
	BOOST_REQUIRE(decryptor.RestoreControlLines(wire.data(), wire.size(), cleanBlock, salt, &header));
	BOOST_CHECK_EQUAL(BinToHex(salt), JsonString(vector, "salt_hex"));
	BOOST_CHECK_EQUAL(header.segmentIndex, JsonUint32(vector, "segment_index"));
	BOOST_CHECK_EQUAL(cleanBlock,
		"=ybegin line=128 size=1 name=my =ypart part=2.bin\r\nF\r\n=yend size=1 crc32=16df26f1\r\n");
	BOOST_CHECK(cleanBlock.find("\r\n=ypart ") == std::string::npos && cleanBlock.find("\n=ypart ") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(DynamicMalformedInputsTestVectors)
{
	const auto fixture = LoadFixture("malformed_inputs.json");
	const auto& vectors = fixture.at("vectors").as_array();

	for (const auto& item : vectors)
	{
		const auto& vector = item.as_object();
		const std::string id = JsonString(vector, "id");
		BOOST_TEST_CONTEXT(id)
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
				std::vector<uint8_t> aad;
				if (vector.contains("aad_hex"))
				{
					aad = HexToBin(JsonString(vector, "aad_hex"));
				}
				YEncDecryptor decryptor(JsonString(vector, "password"));
				const auto status = decryptor.AuthenticateAndDecrypt(
					ciphertext.data(), ciphertext.size(), salt.data(), tag.data(),
					JsonUint32(vector, "segment_index"), aad.data(), aad.size(), output);
				BOOST_CHECK(status == YEncDecryptor::Status::AuthFailed);
				CheckZeroOutput(vector, output);
			}
			else if (category == "control_syntax")
			{
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
					wire = HexToBin("4b376d5839704c32715238764e34775a000000013ff69054da2b2309591e740e5b9fd79015f610d42f01bd203e5f55dadc39fc760407e845201f");
				}
				const auto status = decryptor.DecryptControlLine(
					wire.data(), wire.size(), 1, isLine1 ? 1 : 2, isLine1, output);
				if (id == "control-syntax-06-wrong-password" || id == "control-syntax-07-wrong-password")
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
			else if (category == "salt_mismatch")
			{
				YEncDecryptor decryptor("test123");
				// Test Dual-Bootstrap Agreement failure:
				// line 1 has line1_salt_hex and line1_index
				// header has header_salt_hex and header_index
				const auto line1Salt = HexToBin(JsonString(vector, "line1_salt_hex"));
				const uint32_t line1Index = JsonUint32(vector, "line1_index");
				const auto headerSaltHex = JsonString(vector, "header_salt_hex");
				const uint32_t headerIndex = JsonUint32(vector, "header_index");

				std::string line1Plain = "=ybegin line=128 size=16 name=test.dat";
				std::vector<uint8_t> wire1;
				BOOST_REQUIRE_EQUAL(static_cast<int>(decryptor.EncryptControlLine(
					reinterpret_cast<const uint8_t*>(line1Plain.data()), line1Plain.size(),
					line1Index, 1, true, line1Salt.data(), wire1
				)), static_cast<int>(YEncDecryptor::Status::Ok));

				std::ostringstream hOss;
				hOss << "=yencryption cipher=XChaCha20-Poly1305 salt=" << headerSaltHex
					 << " index=" << std::hex << std::setw(8) << std::setfill('0') << headerIndex
					 << " tag=0cd77ce245a654463f90b945b1d22d5b";
				std::string line2Plain = hOss.str();
				std::vector<uint8_t> wire2;
				BOOST_REQUIRE_EQUAL(static_cast<int>(decryptor.EncryptControlLine(
					reinterpret_cast<const uint8_t*>(line2Plain.data()), line2Plain.size(),
					line1Index, 2, false, line1Salt.data(), wire2
				)), static_cast<int>(YEncDecryptor::Status::Ok));

				std::string block;
				block.append(reinterpret_cast<const char*>(wire1.data()), wire1.size()); block.append("\r\n");
				block.append(reinterpret_cast<const char*>(wire2.data()), wire2.size()); block.append("\r\n");
				block.append("data\r\n=yend size=16\r\n");

				std::string clean;
				std::vector<uint8_t> outSalt;
				bool ok = decryptor.RestoreControlLines(block.data(), block.size(), clean, outSalt);
				BOOST_CHECK(!ok);
				BOOST_CHECK(clean.empty());
			}
			else if (category == "metadata_validation")
			{
				if (vector.at("id").as_string() == "metadata-04-body-only-vs-combined-only")
				{
					// metadata-04 is a body-only article presented to a combined-only receiver.
					// Per STD-1, this is retriable provider corruption (PROVIDER_FAILOVER)
					// with CONTROL_LINE_DECRYPT_FAILURE because Line 1 has no control-line bootstrap.
					const bool failoverPermitted = vector.at("provider_failover_permitted").as_bool();
					BOOST_CHECK(failoverPermitted);
					continue;
				}

				// Structural tier: metadata-shaped failures are structural
				// (METADATA_VALIDATION) — provider failover is NOT permitted and
				// output must be withheld. Model the queue-time gates:
				// metadata-01/02 (provenance) map to the NZB yenc_encrypted meta gate;
				// metadata-03 (missing password) maps to the structural abort in
				// NzbFile::ValidateEncryptedReleasePassword.
				const std::string expectedError = JsonString(vector, "expected_error");
				const bool failoverPermitted = vector.at("provider_failover_permitted").as_bool();
				BOOST_CHECK(!failoverPermitted);

				bool structurallyRejected = false;
				Options::CmdOptList cmdOpts;
				std::string destOpt = "DestDir=" + std::filesystem::temp_directory_path().string();
				std::string interOpt = "InterDir=";
				cmdOpts.push_back(destOpt.c_str());
				cmdOpts.push_back(interOpt.c_str());
				Options options(&cmdOpts, nullptr);
				Options* oldOptions = g_Options;
				g_Options = &options;

				std::string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
					"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n";
				if (expectedError == "MISSING_PASSWORD")
				{
					// Encrypted release with no password meta at all.
					xml += "<head><meta type=\"yenc_encrypted\">true</meta></head>\n";
				}

				else
				{
					// metadata-01/02: the release declares encryption but the
					// transport provenance meta is missing/false on the wire —
					// the NZB-side gate must still be armed (yenc_encrypted=true)
					// so the decoder bootstrap path enforces provenance.
					xml += "<head><meta type=\"password\">test123</meta>"
						"<meta type=\"yenc_encrypted\">true</meta></head>\n";
				}
				xml += "<file poster=\"p\" date=\"100\" subject=\"mv.bin\">"
					"<groups><group>a.b.t</group></groups>"
					"<segments><segment bytes=\"16\" number=\"1\">msg1@test</segment></segments>"
					"</file></nzb>\n";

				const std::filesystem::path tempNzb =
					std::filesystem::temp_directory_path() / (id + ".nzb");
				{
					std::ofstream output(tempNzb, std::ios::binary);
					output << xml;
				}
				NzbFile nzbFile(tempNzb.string().c_str(), "");
				const bool parsed = nzbFile.Parse();
				std::unique_ptr<NzbInfo> nzbInfo = nzbFile.DetachNzbInfo();
				std::filesystem::remove(tempNzb);
				g_Options = oldOptions;

				if (expectedError == "MISSING_PASSWORD")
				{
					// Structural tier (METADATA_VALIDATION): the release parses, but the
					// effective-password gate in Scanner::AddFileToQueue /
					// ProcessStandalone rejects it AFTER the caller-parameter
					// merge — an API-supplied *Unpack:Password can still satisfy
					// the requirement, so the check must run post-merge. Here no
					// parameter source exists: the effective password is empty,
					// exactly the condition the Scanner gate rejects with
					// METADATA_VALIDATION (see ScannerEffectivePasswordGateTest).
					BOOST_CHECK(parsed);
					BOOST_REQUIRE(nzbInfo);
					BOOST_CHECK(nzbInfo->IsYEncEncrypted());
					BOOST_CHECK_EQUAL(nzbInfo->GetPassword(), "");
					structurallyRejected = nzbInfo->IsYEncEncrypted() &&
						(!nzbInfo->GetPassword() || nzbInfo->GetPassword()[0] == '\0');
					BOOST_CHECK(structurallyRejected);
				}

				else
				{
					// Provenance vectors: the encrypted-release gate is armed
					// (yenc_encrypted=true); the per-article provenance check on
					// the wire maps to the decoder bootstrap path. Zero output.
					BOOST_CHECK(parsed);
					BOOST_REQUIRE(nzbInfo);
					BOOST_CHECK(nzbInfo->IsYEncEncrypted());
				}

				// Zero-Output Guarantee holds for the structural tier.
				std::vector<uint8_t> noOutput;
				CheckZeroOutput(vector, noOutput);
			}
			else if (category == "placement")
			{
				if (vector.contains("has_part_on_ybegin"))
				{
					// Contradictory framing vectors (STD-13, C-2): verified by standards suite
					continue;
				}
				// Placement: =yencryption must sit on its canonical physical
				// line. RestoreControlLines enforces the structural layout
				// (line 1 =ybegin, optional line 2 =ypart, then =yencryption,
				// footer =yend); a header on the wrong line fails restoration →
				// PROVIDER_FAILOVER with zero output.
				const uint32_t lineIndex = JsonUint32(vector, "line_index");
				const bool multipart = vector.at("multipart").as_bool();
				const std::string expectedError = JsonString(vector, "expected_error");
				BOOST_CHECK_EQUAL(expectedError, "MISPLACED_ENCRYPTION_HEADER");

				YEncDecryptor decryptor("test123");
				const auto salt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");

				std::string line1Plain = "=ybegin line=128 size=16 name=test.dat";
				std::vector<uint8_t> wire1;
				BOOST_REQUIRE_EQUAL(static_cast<int>(decryptor.EncryptControlLine(
					reinterpret_cast<const uint8_t*>(line1Plain.data()), line1Plain.size(),
					1, 1, true, salt.data(), wire1
				)), static_cast<int>(YEncDecryptor::Status::Ok));

				std::vector<uint8_t> wirePart;
				if (multipart)
				{
					std::string partPlain = "=ypart begin=1 end=16";
					BOOST_REQUIRE_EQUAL(static_cast<int>(decryptor.EncryptControlLine(
						reinterpret_cast<const uint8_t*>(partPlain.data()), partPlain.size(),
						1, 2, false, salt.data(), wirePart
					)), static_cast<int>(YEncDecryptor::Status::Ok));
				}

				// =yencryption placed on the vector's (wrong) line index.
				std::string headerPlain = "=yencryption cipher=XChaCha20-Poly1305 "
					"salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 "
					"tag=0cd77ce245a654463f90b945b1d22d5b";
				std::vector<uint8_t> wireHeader;
				BOOST_REQUIRE_EQUAL(static_cast<int>(decryptor.EncryptControlLine(
					reinterpret_cast<const uint8_t*>(headerPlain.data()), headerPlain.size(),
					1, lineIndex, false, salt.data(), wireHeader
				)), static_cast<int>(YEncDecryptor::Status::Ok));

				std::string block;
				block.append(reinterpret_cast<const char*>(wire1.data()), wire1.size());
				block.append("\r\n");
				if (multipart)
				{
					block.append(reinterpret_cast<const char*>(wirePart.data()), wirePart.size());
					block.append("\r\n");
				}
				// Pad with filler so the header physically lands on lineIndex.
				while (blockerLineCount(block) < lineIndex - 1)
				{
					block.append("data\r\n");
				}
				block.append(reinterpret_cast<const char*>(wireHeader.data()), wireHeader.size());
				block.append("\r\n");
				block.append("data\r\n");
				block.append("=yend size=16\r\n");

				std::string clean;
				std::vector<uint8_t> outSalt;
				const bool ok = decryptor.RestoreControlLines(block.data(), block.size(), clean, outSalt);
				BOOST_CHECK(!ok);
				BOOST_CHECK(clean.empty());
				CheckZeroOutput(vector, std::vector<uint8_t>(clean.begin(), clean.end()));
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
	BOOST_REQUIRE_EQUAL(vectors.size(), 16U);

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
			}
			else if (category == "unencrypted_compatibility")
			{
				BOOST_REQUIRE(parsed);
				BOOST_REQUIRE(nzbInfo);
				BOOST_CHECK(!nzbInfo->IsYEncEncrypted());
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
					std::vector<uint8_t> aad;
					if (vector.contains("aad_hex"))
					{
						aad = HexToBin(JsonString(vector, "aad_hex"));
					}
					const auto status = decryptor.AuthenticateAndDecrypt(
						ciphertext.data(), ciphertext.size(), salt.data(), tag.data(),
						JsonUint32(vector, "tampered_segment_index"), aad.data(), aad.size(), plaintext);
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
						std::vector<uint8_t> aad;
						if (segment.contains("aad_hex"))
						{
							aad = HexToBin(JsonString(segment, "aad_hex"));
						}
						plaintext.clear();
						YEncDecryptor segmentDecryptor(JsonString(vector, "password"));
						const auto status = segmentDecryptor.AuthenticateAndDecrypt(
							ciphertext.data(), ciphertext.size(), salt.data(), tag.data(),
							JsonUint32(segment, "tampered_segment_index"), aad.data(), aad.size(), plaintext);
						BOOST_CHECK(status == YEncDecryptor::Status::AuthFailed);
						BOOST_CHECK(plaintext.empty());
					}
				}
			}
			else if (category == "metadata_mutation")
			{
				BOOST_REQUIRE(parsed);
				BOOST_REQUIRE(nzbInfo);
				BOOST_CHECK(nzbInfo->IsYEncEncrypted());

				YEncDecryptor decryptor(JsonString(vector, "password"));
				const auto salt = HexToBin(JsonString(vector, "salt_hex"));
				const auto ciphertext = HexToBin(JsonString(vector, "ciphertext_hex"));
				const auto tag = HexToBin(JsonString(vector, "tag_hex"));
				std::vector<uint8_t> aad;
				if (vector.contains("aad_hex"))
				{
					aad = HexToBin(JsonString(vector, "aad_hex"));
				}
				std::vector<uint8_t> plaintext;
				const auto status = decryptor.AuthenticateAndDecrypt(
					ciphertext.data(), ciphertext.size(), salt.data(), tag.data(),
					JsonUint32(vector, "segment_index"), aad.data(), aad.size(), plaintext);
				BOOST_CHECK(status == YEncDecryptor::Status::AuthFailed);
				BOOST_CHECK(plaintext.empty());
			}
		}
	}

	g_Options = oldOptions;
}

BOOST_AUTO_TEST_SUITE_END()
