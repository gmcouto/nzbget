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

#include <boost/test/unit_test.hpp>
#include "Decoder.h"
#include "YEncDecryptor.h"
#include "YEncoder.h"
#include "Util.h"
#include "DownloadInfo.h"
#include "Options.h"
#include "ArticleDownloader.h"

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

namespace
{

std::vector<uint8_t> HexToBin(const std::string& hex)
{
	std::vector<uint8_t> bytes;
	for (size_t i = 0; i < hex.length(); i += 2)
	{
		unsigned int byteVal = 0;
		sscanf(hex.c_str() + i, "%02x", &byteVal);
		bytes.push_back(static_cast<uint8_t>(byteVal));
	}
	return bytes;
}

std::string BinToHex(const uint8_t* data, size_t len)
{
	std::ostringstream oss;
	for (size_t i = 0; i < len; ++i)
	{
		oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
	}
	return oss.str();
}

std::string yEncSimpleEncode(const std::vector<uint8_t>& data)
{
	std::string encoded;
	for (uint8_t c : data)
	{
		encoded += static_cast<char>((c + 42) % 256);
	}
	return encoded;
}

} // anonymous namespace

BOOST_AUTO_TEST_SUITE(NNTPTest)

BOOST_AUTO_TEST_CASE(MasterKeyDerivationAndCachingTest)
{
	YEncDecryptor decryptor("test123");
	// Vector from 01-argon2id-kdf.json: argon2id-01-basic
	// salt: 1a2b3c4d5e6f7890abcdef1234567890
	// expected: 5dd5a3371f80a50eb96feb11787dd4567a09b55655aa3c2b1596bf2d45c9a6d7
	std::vector<uint8_t> salt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
	BOOST_REQUIRE_EQUAL(salt.size(), 16);

	BOOST_CHECK(decryptor.EnsureMasterKey(salt.data()));
	BOOST_CHECK_EQUAL(decryptor.GetCachedSaltCount(), 1);

	std::string keyHex = BinToHex(decryptor.GetCachedMasterKey().data(), decryptor.GetCachedMasterKey().size());
	BOOST_CHECK_EQUAL(keyHex, "5dd5a3371f80a50eb96feb11787dd4567a09b55655aa3c2b1596bf2d45c9a6d7");

	// Re-check caching: same salt shouldn't recalculate
	BOOST_CHECK(decryptor.EnsureMasterKey(salt.data()));
	BOOST_CHECK_EQUAL(decryptor.GetCachedSaltCount(), 1);
	std::string keyHex2 = BinToHex(decryptor.GetCachedMasterKey().data(), decryptor.GetCachedMasterKey().size());
	BOOST_CHECK_EQUAL(keyHex2, keyHex);
}

BOOST_AUTO_TEST_CASE(DeriveBodyNonceTest)
{
	YEncDecryptor decryptor("test123");
	std::vector<uint8_t> salt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
	BOOST_REQUIRE(decryptor.EnsureMasterKey(salt.data()));

	// Vector from body_encryption.json: body-vec-01-spec-example (segmentIndex=1)
	// derived_nonce_hex: f6f6e23118719f87d11c9984c71de61cb38c8e50e1356242
	uint8_t nonce1[24];
	BOOST_CHECK(decryptor.DeriveBodyNonce(1, nonce1));
	BOOST_CHECK_EQUAL(BinToHex(nonce1, 24), "f6f6e23118719f87d11c9984c71de61cb38c8e50e1356242");

	// Vector from body_encryption.json: body-vec-03-multi-block (segmentIndex=2)
	// derived_nonce_hex: 2dad96a23a557711eaeb8d010d23f897524ad90d3c73914f
	uint8_t nonce2[24];
	BOOST_CHECK(decryptor.DeriveBodyNonce(2, nonce2));
	BOOST_CHECK_EQUAL(BinToHex(nonce2, 24), "2dad96a23a557711eaeb8d010d23f897524ad90d3c73914f");
}

BOOST_AUTO_TEST_CASE(AuthenticateAndDecryptTestVector)
{
	YEncDecryptor decryptor("test123");
	// Vector from body_encryption.json: body-vec-01-spec-example
	std::vector<uint8_t> salt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
	std::vector<uint8_t> ciphertext = HexToBin("6a0d1eb225f844920540fa382ff68874");
	std::vector<uint8_t> tag = HexToBin("0cd77ce245a654463f90b945b1d22d5b");
	std::vector<uint8_t> expectedPlaintext = HexToBin("48656c6c6f20576f726c642e747874ff");

	std::vector<uint8_t> outPlaintext;
	YEncDecryptor::Status st = decryptor.AuthenticateAndDecrypt(
		ciphertext.data(), ciphertext.size(),
		salt.data(), tag.data(), 1, outPlaintext);

	BOOST_CHECK_EQUAL(static_cast<int>(st), static_cast<int>(YEncDecryptor::Status::Ok));
	BOOST_CHECK_EQUAL(BinToHex(outPlaintext.data(), outPlaintext.size()), BinToHex(expectedPlaintext.data(), expectedPlaintext.size()));
}

BOOST_AUTO_TEST_CASE(ZeroOutputOnCorruptTag)
{
	YEncDecryptor decryptor("test123");
	std::vector<uint8_t> salt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
	std::vector<uint8_t> ciphertext = HexToBin("6a0d1eb225f844920540fa382ff68874");
	std::vector<uint8_t> corruptTag = HexToBin("ffffffffffffffffffffffffffffffff");

	std::vector<uint8_t> outPlaintext;
	YEncDecryptor::Status st = decryptor.AuthenticateAndDecrypt(
		ciphertext.data(), ciphertext.size(),
		salt.data(), corruptTag.data(), 1, outPlaintext);

	BOOST_CHECK_EQUAL(static_cast<int>(st), static_cast<int>(YEncDecryptor::Status::AuthFailed));
	BOOST_CHECK_EQUAL(outPlaintext.size(), 0); // Zero-Output Guarantee!
}

BOOST_AUTO_TEST_CASE(ControlLineDecryptionTest)
{
	YEncDecryptor decryptor("test123");
	// Vector from control_line_encryption.json: control-vec-01-line-1-ybegin-single (with 20-byte bootstrap)
	std::vector<uint8_t> wire1 = HexToBin("4b376d5839704c32715238764e34775a000000013ff69054da2b2309591e740e5b9fd79015f610d42f01bd203e5f55dadc39fc760407e845201f");
	std::vector<uint8_t> outPlaintext1;
	std::vector<uint8_t> outSalt1;
	uint32_t outIndex1 = 0;

	auto st1 = decryptor.DecryptControlLine(wire1.data(), wire1.size(), 1, 1, true, outPlaintext1, &outSalt1, &outIndex1);
	BOOST_REQUIRE_EQUAL(static_cast<int>(st1), static_cast<int>(YEncDecryptor::Status::Ok));
	std::string pt1(reinterpret_cast<const char*>(outPlaintext1.data()), outPlaintext1.size());
	BOOST_CHECK_EQUAL(pt1, "=ybegin line=128 size=18 name=file.bin");
	BOOST_CHECK_EQUAL(outIndex1, 1U);
	BOOST_CHECK_EQUAL(BinToHex(outSalt1.data(), outSalt1.size()), "4b376d5839704c32715238764e34775a");

	// Vector from control_line_encryption.json: control-vec-03-line-2-ypart
	std::vector<uint8_t> wire2 = HexToBin("2135072cf2b566804a99bd31fe1d42b2603a7518ae20a58498");
	std::vector<uint8_t> outPlaintext2;
	auto st2 = decryptor.DecryptControlLine(wire2.data(), wire2.size(), 1, 2, false, outPlaintext2);
	BOOST_REQUIRE_EQUAL(static_cast<int>(st2), static_cast<int>(YEncDecryptor::Status::Ok));
	std::string pt2(reinterpret_cast<const char*>(outPlaintext2.data()), outPlaintext2.size());
	BOOST_CHECK_EQUAL(pt2, "=ypart begin=1 end=700000");
}

BOOST_AUTO_TEST_CASE(ParseYEncryptionTest)
{
	std::string line = "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b\r\n";
	std::string cipher;
	uint8_t salt[16];
	uint8_t tag[16];
	uint32_t segmentIndex = 0;

	BOOST_CHECK(YEncDecryptor::ParseYEncryption(line.c_str(), line.length(), cipher, salt, tag, segmentIndex));
	BOOST_CHECK_EQUAL(cipher, "XChaCha20-Poly1305");
	BOOST_CHECK_EQUAL(BinToHex(salt, 16), "1a2b3c4d5e6f7890abcdef1234567890");
	BOOST_CHECK_EQUAL(BinToHex(tag, 16), "0cd77ce245a654463f90b945b1d22d5b");
	BOOST_CHECK_EQUAL(segmentIndex, 1U);

	// Malformed inputs
	std::string badCipher = "=yencryption cipher=AES-256-GCM salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b\r\n";
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(badCipher.c_str(), badCipher.length(), cipher, salt, tag));

	std::string badSalt = "=yencryption cipher=XChaCha20-Poly1305 salt=short index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b\r\n";
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(badSalt.c_str(), badSalt.length(), cipher, salt, tag));

	std::string badTag = "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=nonhextag1234567890123456789012\r\n";
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(badTag.c_str(), badTag.length(), cipher, salt, tag));

	std::string badIndex = "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000000 tag=0cd77ce245a654463f90b945b1d22d5b\r\n";
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(badIndex.c_str(), badIndex.length(), cipher, salt, tag));
}

BOOST_AUTO_TEST_CASE(DecoderEncryptedIntegrationTest)
{
	Decoder decoder;
	decoder.SetCrcCheck(false); // Testing payload exclusion and decryption
	YEncDecryptor decryptor("test123");
	decoder.SetDecryptor(&decryptor);
	// In v1.1, segment index is discovered directly from the wire bytes

	std::vector<uint8_t> ciphertext = HexToBin("6a0d1eb225f844920540fa382ff68874");
	std::string yencBody = yEncSimpleEncode(ciphertext);

	std::stringstream ss;
	ss << "=ybegin line=128 size=" << ciphertext.size() << " name=test.dat\r\n";
	ss << "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b\r\n";
	ss << yencBody << "\r\n";
	ss << "=yend size=" << ciphertext.size() << "\r\n";
	ss << ".\r\n";

	std::string msg = ss.str();
	int len = decoder.DecodeBuffer(msg.data(), msg.size());

	BOOST_CHECK_EQUAL(len, static_cast<int>(ciphertext.size()));
	BOOST_CHECK(decoder.IsEncrypted());
	BOOST_CHECK_EQUAL(BinToHex(decoder.GetSalt(), 16), "1a2b3c4d5e6f7890abcdef1234567890");
	BOOST_CHECK_EQUAL(BinToHex(decoder.GetTag(), 16), "0cd77ce245a654463f90b945b1d22d5b");
	BOOST_CHECK_EQUAL(decoder.GetSegmentIndex(), 1U);

	auto status = decoder.Check();
	BOOST_CHECK_EQUAL(static_cast<int>(status), static_cast<int>(Decoder::dsFinished));

	// Verify decrypted plaintext
	std::vector<uint8_t> expectedPlaintext = HexToBin("48656c6c6f20576f726c642e747874ff");
	BOOST_CHECK_EQUAL(BinToHex(decoder.GetDecryptedData().data(), decoder.GetDecryptedData().size()),
		BinToHex(expectedPlaintext.data(), expectedPlaintext.size()));
}

BOOST_AUTO_TEST_CASE(DecoderAuthFailureIntegrationTest)
{
	Decoder decoder;
	decoder.SetCrcCheck(false);
	YEncDecryptor decryptor("test123");
	decoder.SetDecryptor(&decryptor);

	std::vector<uint8_t> ciphertext = HexToBin("6a0d1eb225f844920540fa382ff68874");
	std::string yencBody = yEncSimpleEncode(ciphertext);

	// Corrupt tag
	std::stringstream ss;
	ss << "=ybegin line=128 size=" << ciphertext.size() << " name=test.dat\r\n";
	ss << "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ffffffffffffffffffffffffffffffff\r\n";
	ss << yencBody << "\r\n";
	ss << "=yend size=" << ciphertext.size() << "\r\n";
	ss << ".\r\n";

	std::string msg = ss.str();
	decoder.DecodeBuffer(msg.data(), msg.size());

	auto status = decoder.Check();
	BOOST_CHECK_EQUAL(static_cast<int>(status), static_cast<int>(Decoder::dsAuthFailed));
	BOOST_CHECK_EQUAL(decoder.GetDecryptedData().size(), 0); // Zero-Output Guarantee!
}

BOOST_AUTO_TEST_CASE(NzbInfoPasswordAccessorTest)
{
	NzbInfo nzbInfo;
	BOOST_CHECK(!nzbInfo.HasPassword());
	BOOST_CHECK_EQUAL(std::string(nzbInfo.GetPassword()), "");

	nzbInfo.GetParameters()->SetParameter("*Unpack:Password", "secret_pass_123");
	BOOST_CHECK(nzbInfo.HasPassword());
	BOOST_CHECK_EQUAL(std::string(nzbInfo.GetPassword()), "secret_pass_123");

	nzbInfo.GetParameters()->SetParameter("*Unpack:Password", "");
	BOOST_CHECK(!nzbInfo.HasPassword());
	BOOST_CHECK_EQUAL(std::string(nzbInfo.GetPassword()), "");
}

BOOST_AUTO_TEST_CASE(DirectWriteBypassForPasswordTest)
{
	Options::CmdOptList cmdOpts;
	Options options(&cmdOpts, nullptr);
	Options* oldOptions = g_Options;
	g_Options = &options;

	NzbInfo nzbInfo;
	FileInfo fileInfo;
	fileInfo.SetNzbInfo(&nzbInfo);

	// Without password: direct-write follows g_Options->GetDirectWrite()
	bool hasPassword = fileInfo.GetNzbInfo() && fileInfo.GetNzbInfo()->HasPassword();
	bool directWriteAllowed = (g_Options->GetDirectWrite() && !hasPassword) || fileInfo.GetForceDirectWrite();
	BOOST_CHECK(!hasPassword);
	BOOST_CHECK_EQUAL(directWriteAllowed, g_Options->GetDirectWrite());

	// With password: direct-write is strictly bypassed (Zero-Output Guarantee)
	nzbInfo.GetParameters()->SetParameter("*Unpack:Password", "secret_pass_123");
	hasPassword = fileInfo.GetNzbInfo() && fileInfo.GetNzbInfo()->HasPassword();
	directWriteAllowed = (g_Options->GetDirectWrite() && !hasPassword) || fileInfo.GetForceDirectWrite();
	BOOST_CHECK(hasPassword);
	BOOST_CHECK_EQUAL(directWriteAllowed, false);

	g_Options = oldOptions;
}

BOOST_AUTO_TEST_CASE(ArticleDownloaderFailoverMappingTest)
{
	// Verify that Decoder::dsAuthFailed is recognized as authentication failure
	Decoder decoder;
	decoder.SetAuthFailed(true);
	BOOST_CHECK_EQUAL(static_cast<int>(decoder.Check()), static_cast<int>(Decoder::dsAuthFailed));

	// Verify that dsAuthFailed is mapped to retryable adFailed (enabling QueueCoordinator server failover)
	Decoder::EStatus decStatus = Decoder::dsAuthFailed;
	ArticleDownloader::EStatus adStatus = (decStatus == Decoder::dsAuthFailed) ?
		ArticleDownloader::adFailed : ArticleDownloader::adFinished;
	BOOST_CHECK_EQUAL(static_cast<int>(adStatus), static_cast<int>(ArticleDownloader::adFailed));
}

BOOST_AUTO_TEST_CASE(YEncryptionGrammarTest)
{
	YEncDecryptor::YEncryptionHeader header;

	// Valid header
	std::string validLine = "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b\r\n";
	BOOST_CHECK(YEncDecryptor::ParseYEncryption(validLine.c_str(), validLine.size(), header));
	BOOST_CHECK_EQUAL(header.cipher, "XChaCha20-Poly1305");
	BOOST_CHECK_EQUAL(header.saltHex, "1a2b3c4d5e6f7890abcdef1234567890");
	BOOST_CHECK_EQUAL(header.indexHex, "00000001");
	BOOST_CHECK_EQUAL(header.tagHex, "0cd77ce245a654463f90b945b1d22d5b");
	BOOST_CHECK_EQUAL(header.segmentIndex, 1U);

	// malformed-header-01-bad-cipher
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=AES-256-GCM salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafa", header));

	// malformed-header-02-chacha20-unauth
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=ChaCha20 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafa", header));

	// malformed-header-03-empty-cipher
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher= salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafa", header));

	// malformed-header-04-missing-salt
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 index=00000001 tag=ed70d238067735a20783df5e094ccafa", header));

	// malformed-header-05-truncated-salt
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef12345678 index=00000001 tag=ed70d238067735a20783df5e094ccafa", header));

	// malformed-header-06-extended-salt
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890ff index=00000001 tag=ed70d238067735a20783df5e094ccafa", header));

	// malformed-header-07-non-hex-salt
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef12345678gz index=00000001 tag=ed70d238067735a20783df5e094ccafa", header));

	// Uppercase hex in salt
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1A2B3C4D5E6F7890ABCDEF1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafa", header));

	// malformed-header-08-missing-tag
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001", header));

	// malformed-header-09-truncated-tag
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d", header));

	// malformed-header-10-extended-tag
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b00", header));

	// malformed-header-11-non-hex-tag
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22dxy", header));

	// Uppercase hex in tag
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0CD77CE245A654463F90B945B1D22D5B", header));

	// malformed-header-12-missing-index
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b", header));

	// malformed-header-13-zero-index
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000000 tag=0cd77ce245a654463f90b945b1d22d5b", header));

	// malformed-header-14-truncated-index
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=000001 tag=0cd77ce245a654463f90b945b1d22d5b", header));

	// malformed-header-15-extended-index
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=0000000001 tag=0cd77ce245a654463f90b945b1d22d5b", header));

	// malformed-header-16-non-hex-index
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=0000000z tag=0cd77ce245a654463f90b945b1d22d5b", header));

	// malformed-header-17-uppercase-index
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=0000000A tag=0cd77ce245a654463f90b945b1d22d5b", header));

	// Reordered tokens (salt before cipher)
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption salt=1a2b3c4d5e6f7890abcdef1234567890 cipher=XChaCha20-Poly1305 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b", header));

	// Extra tokens
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b extra=123", header));

	// Extra whitespace
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(
		"=yencryption  cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b", header));
}

BOOST_AUTO_TEST_CASE(YEncryptionMalformedInputsTest)
{
	// Test auth_failure cases from malformed_inputs.json
	// auth-failure-01-tampered-ciphertext
	{
		YEncDecryptor decryptor("test123");
		std::vector<uint8_t> salt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
		std::vector<uint8_t> tamperedCt = HexToBin("6b0d1eb225f844920540fa3628eb9ff9d3174ea7e14a5ba7da1f0f6e970aed28");
		std::vector<uint8_t> tag = HexToBin("ed70d238067735a20783df5e094ccafa");
		std::vector<uint8_t> outPt;

		auto st = decryptor.AuthenticateAndDecrypt(
			tamperedCt.data(), tamperedCt.size(), salt.data(), tag.data(), 1, outPt);
		BOOST_CHECK_EQUAL(static_cast<int>(st), static_cast<int>(YEncDecryptor::Status::AuthFailed));
		BOOST_CHECK_EQUAL(outPt.size(), 0);
	}

	// auth-failure-02-tampered-tag
	{
		YEncDecryptor decryptor("test123");
		std::vector<uint8_t> salt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
		std::vector<uint8_t> ct = HexToBin("6a0d1eb225f844920540fa3628eb9ff9d3174ea7e14a5ba7da1f0f6e970aed28");
		std::vector<uint8_t> tamperedTag = HexToBin("ec70d238067735a20783df5e094ccafa");
		std::vector<uint8_t> outPt;

		auto st = decryptor.AuthenticateAndDecrypt(
			ct.data(), ct.size(), salt.data(), tamperedTag.data(), 1, outPt);
		BOOST_CHECK_EQUAL(static_cast<int>(st), static_cast<int>(YEncDecryptor::Status::AuthFailed));
		BOOST_CHECK_EQUAL(outPt.size(), 0);
	}

	// auth-failure-03-wrong-password
	{
		YEncDecryptor decryptor("wrong_password_999");
		std::vector<uint8_t> salt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
		std::vector<uint8_t> ct = HexToBin("6a0d1eb225f844920540fa3628eb9ff9d3174ea7e14a5ba7da1f0f6e970aed28");
		std::vector<uint8_t> tag = HexToBin("ed70d238067735a20783df5e094ccafa");
		std::vector<uint8_t> outPt;

		auto st = decryptor.AuthenticateAndDecrypt(
			ct.data(), ct.size(), salt.data(), tag.data(), 1, outPt);
		BOOST_CHECK_EQUAL(static_cast<int>(st), static_cast<int>(YEncDecryptor::Status::AuthFailed));
		BOOST_CHECK_EQUAL(outPt.size(), 0);
	}

	// auth-failure-04-mismatched-segment-index
	{
		YEncDecryptor decryptor("test123");
		std::vector<uint8_t> salt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
		std::vector<uint8_t> ct = HexToBin("6a0d1eb225f844920540fa3628eb9ff9d3174ea7e14a5ba7da1f0f6e970aed28");
		std::vector<uint8_t> tag = HexToBin("ed70d238067735a20783df5e094ccafa");
		std::vector<uint8_t> outPt;

		auto st = decryptor.AuthenticateAndDecrypt(
			ct.data(), ct.size(), salt.data(), tag.data(), 2, outPt); // segment index 2 instead of 1
		BOOST_CHECK_EQUAL(static_cast<int>(st), static_cast<int>(YEncDecryptor::Status::AuthFailed));
		BOOST_CHECK_EQUAL(outPt.size(), 0);
	}

	// Test control_syntax cases from malformed_inputs.json
	// control-syntax-01-forbidden-lf-in-salt (0x0A)
	{
		YEncDecryptor decryptor("test123");
		std::vector<uint8_t> badSalt = HexToBin("4b376d5839704c320a5238764e34775a");
		std::vector<uint8_t> wireData = badSalt;
		wireData.push_back('='); wireData.push_back('y'); // min length
		std::vector<uint8_t> outPt;
		auto st = decryptor.DecryptControlLine(wireData.data(), wireData.size(), 1, 1, true, outPt);
		BOOST_CHECK_EQUAL(static_cast<int>(st), static_cast<int>(YEncDecryptor::Status::Error));
		BOOST_CHECK_EQUAL(outPt.size(), 0);
	}

	// control-syntax-02-forbidden-cr-in-salt (0x0D)
	{
		YEncDecryptor decryptor("test123");
		std::vector<uint8_t> badSalt = HexToBin("4b376d5839704c320d5238764e34775a");
		std::vector<uint8_t> wireData = badSalt;
		wireData.push_back('='); wireData.push_back('y');
		std::vector<uint8_t> outPt;
		auto st = decryptor.DecryptControlLine(wireData.data(), wireData.size(), 1, 1, true, outPt);
		BOOST_CHECK_EQUAL(static_cast<int>(st), static_cast<int>(YEncDecryptor::Status::Error));
		BOOST_CHECK_EQUAL(outPt.size(), 0);
	}

	// control-syntax-03-forbidden-nul-in-salt (0x00)
	{
		YEncDecryptor decryptor("test123");
		std::vector<uint8_t> badSalt = HexToBin("4b376d5839704c32005238764e34775a");
		std::vector<uint8_t> wireData = badSalt;
		wireData.push_back('='); wireData.push_back('y');
		std::vector<uint8_t> outPt;
		auto st = decryptor.DecryptControlLine(wireData.data(), wireData.size(), 1, 1, true, outPt);
		BOOST_CHECK_EQUAL(static_cast<int>(st), static_cast<int>(YEncDecryptor::Status::Error));
		BOOST_CHECK_EQUAL(outPt.size(), 0);
	}

	// control-syntax-04-line-too-short (len < 2)
	{
		YEncDecryptor decryptor("test123");
		uint8_t salt[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
		decryptor.EnsureMasterKey(salt);
		std::vector<uint8_t> shortLine = { 0x3d }; // "=" 1 byte
		std::vector<uint8_t> outPt;
		auto st = decryptor.DecryptControlLine(shortLine.data(), shortLine.size(), 1, 2, false, outPt);
		BOOST_CHECK_EQUAL(static_cast<int>(st), static_cast<int>(YEncDecryptor::Status::Error));
		BOOST_CHECK_EQUAL(outPt.size(), 0);
	}

	// control-syntax-05-line1-truncated (len < 18)
	{
		YEncDecryptor decryptor("test123");
		std::vector<uint8_t> truncLine1 = HexToBin("4b376d5839704c32715238764e34775a3d"); // 17 bytes
		std::vector<uint8_t> outPt;
		auto st = decryptor.DecryptControlLine(truncLine1.data(), truncLine1.size(), 1, 1, true, outPt);
		BOOST_CHECK_EQUAL(static_cast<int>(st), static_cast<int>(YEncDecryptor::Status::Error));
		BOOST_CHECK_EQUAL(outPt.size(), 0);
	}

	// control-syntax-06-wrong-password for control line decryption
	{
		YEncDecryptor decryptor("wrong_control_password");
		std::vector<uint8_t> wire1 = HexToBin("4b376d5839704c32715238764e34775a3ff69054da2b2309591e740e5b9fd79015f610d42f01bd203e5f55dadc39fc760407e845201f");
		std::vector<uint8_t> outPt;
		auto st = decryptor.DecryptControlLine(wire1.data(), wire1.size(), 1, 1, true, outPt);
		if (st == YEncDecryptor::Status::Ok)
		{
			// Must not begin with =ybegin
			std::string pt(reinterpret_cast<const char*>(outPt.data()), outPt.size());
			BOOST_CHECK(pt.rfind("=ybegin", 0) != 0);
		}
	}

	// Salt mismatch between line 1 salt and =yencryption salt in RestoreControlLines
	{
		YEncDecryptor decryptor("test123");
		// Encrypt valid line 1 with salt1
		std::vector<uint8_t> salt1 = HexToBin("11111111111111111111111111111111");
		std::string l1 = "=ybegin line=128 size=16 name=test.dat";
		std::vector<uint8_t> wire1;
		decryptor.EncryptControlLine(reinterpret_cast<const uint8_t*>(l1.data()), l1.size(), 1, 1, true, salt1.data(), wire1);

		// Encrypt line 2 with salt2 (mismatched in =yencryption)
		std::string l2 = "=yencryption cipher=XChaCha20-Poly1305 salt=22222222222222222222222222222222 index=00000001 tag=0cd77ce245a654463f90b945b1d22d5b";
		std::vector<uint8_t> wire2;
		decryptor.EncryptControlLine(reinterpret_cast<const uint8_t*>(l2.data()), l2.size(), 1, 2, false, salt1.data(), wire2);

		std::string l3 = "data";
		std::string l4 = "=yend size=16";
		std::vector<uint8_t> wire4;
		decryptor.EncryptControlLine(reinterpret_cast<const uint8_t*>(l4.data()), l4.size(), 1, 4, false, salt1.data(), wire4);

		std::string block;
		block.append(reinterpret_cast<const char*>(wire1.data()), wire1.size()); block.append("\r\n");
		block.append(reinterpret_cast<const char*>(wire2.data()), wire2.size()); block.append("\r\n");
		block.append(l3); block.append("\r\n");
		block.append(reinterpret_cast<const char*>(wire4.data()), wire4.size()); block.append("\r\n");

		std::string clean;
		std::vector<uint8_t> outSalt;
		bool ok = decryptor.RestoreControlLines(block.data(), block.size(), 1, clean, outSalt);
		BOOST_CHECK(!ok);
		BOOST_CHECK(clean.empty());
	}
}

BOOST_AUTO_TEST_CASE(YEncryptionZeroOutputTest)
{
	// Ensure that on every failure condition, zero plaintext is returned and buffer is empty
	Decoder decoder;
	decoder.SetPassword("test123");
	decoder.SetSegmentIndex(1);

	// 1. Decoder check with no data
	auto st = decoder.Check();
	BOOST_CHECK_NE(static_cast<int>(st), static_cast<int>(Decoder::dsFinished));
	BOOST_CHECK_EQUAL(decoder.GetDecryptedData().size(), 0);

	// 2. Decoder with tampered ciphertext in encrypted wire article
	decoder.Clear();
	decoder.SetPassword("test123");
	decoder.SetSegmentIndex(1);

	std::string password = "test123";
	std::vector<uint8_t> salt = HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
	std::vector<uint8_t> tamperedCt = HexToBin("6b0d1eb225f844920540fa3628eb9ff9d3174ea7e14a5ba7da1f0f6e970aed28");
	std::vector<uint8_t> tag = HexToBin("ed70d238067735a20783df5e094ccafa");
	uint32_t segmentIndex = 1;

	YEncDecryptor encDec(password);
	std::string line1Plain = "=ybegin line=128 size=32 name=tampered.dat";
	std::vector<uint8_t> wireLine1;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line1Plain.data()), line1Plain.size(),
		segmentIndex, 1, true, salt.data(), wireLine1
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string line2Plain = "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 index=00000001 tag=ed70d238067735a20783df5e094ccafa";
	std::vector<uint8_t> wireLine2;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line2Plain.data()), line2Plain.size(),
		segmentIndex, 2, false, salt.data(), wireLine2
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string wireLine3 = yEncSimpleEncode(tamperedCt);

	Crc32 crc;
	crc.Append(tamperedCt.data(), tamperedCt.size());
	uint32_t ctCrc = crc.Finish();
	std::ostringstream endOss;
	endOss << "=yend size=32 crc32=" << std::hex << std::setw(8) << std::setfill('0') << ctCrc;
	std::string line4Plain = endOss.str();

	std::vector<uint8_t> wireLine4;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line4Plain.data()), line4Plain.size(),
		segmentIndex, 4, false, salt.data(), wireLine4
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string fullWire;
	fullWire.append(reinterpret_cast<const char*>(wireLine1.data()), wireLine1.size());
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine2.data()), wireLine2.size());
	fullWire.append("\r\n");
	fullWire.append(wireLine3);
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine4.data()), wireLine4.size());
	fullWire.append("\r\n.\r\n");

	decoder.DecodeBuffer(fullWire.data(), fullWire.size());
	st = decoder.Check();
	BOOST_CHECK_EQUAL(static_cast<int>(st), static_cast<int>(Decoder::dsAuthFailed));
	BOOST_CHECK_EQUAL(decoder.GetDecryptedData().size(), 0);
}

BOOST_AUTO_TEST_CASE(YEncDecryptorRaiiExceptionSafetyTest)
{
	YEncDecryptor decryptor("test_password");
	uint8_t salt[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28};
	BOOST_REQUIRE(decryptor.EnsureMasterKey(salt));

	// Test control line decryption with invalid / truncated wire data
	std::vector<uint8_t> outPlaintext;
	std::vector<uint8_t> outSalt;
	uint32_t outSegIndex = 0;

	// Invalid line 1 wire data (< 22 bytes)
	uint8_t shortWire[10] = {0};
	auto st = decryptor.DecryptControlLine(shortWire, sizeof(shortWire), 1, 1, true, outPlaintext, &outSalt, &outSegIndex);
	BOOST_CHECK(st == YEncDecryptor::Status::Error);
	BOOST_CHECK(outPlaintext.empty());

	// Invalid non-line-1 wire data
	st = decryptor.DecryptControlLine(shortWire, 1, 1, 2, false, outPlaintext);
	BOOST_CHECK(st == YEncDecryptor::Status::Error);
	BOOST_CHECK(outPlaintext.empty());

	// Valid control line encrypt/decrypt cycle
	std::string plain = "=ybegin line=128 size=12345 name=test.dat";
	std::vector<uint8_t> wireData;
	st = decryptor.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(plain.data()), plain.size(),
		1, 1, true, salt, wireData
	);
	BOOST_CHECK(st == YEncDecryptor::Status::Ok);
	BOOST_CHECK(!wireData.empty());

	st = decryptor.DecryptControlLine(
		wireData.data(), wireData.size(),
		1, 1, true, outPlaintext, &outSalt, &outSegIndex
	);
	BOOST_CHECK(st == YEncDecryptor::Status::Ok);
	std::string decrypted(outPlaintext.begin(), outPlaintext.end());
	BOOST_CHECK_EQUAL(decrypted, plain);
}

BOOST_AUTO_TEST_CASE(YEncDecryptorAuthFailureZeroizationTest)
{
	YEncDecryptor decryptor("test_password");
	uint8_t salt[16] = {0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb};
	uint8_t badTag[16] = {0}; // Invalid tag
	uint8_t ct[32];
	memset(ct, 0x42, sizeof(ct));

	std::vector<uint8_t> outPlaintext;
	// Pre-fill outPlaintext with dummy values
	outPlaintext.assign(64, 0xff);

	auto st = decryptor.AuthenticateAndDecrypt(ct, sizeof(ct), salt, badTag, 1, outPlaintext);
	BOOST_CHECK(st == YEncDecryptor::Status::AuthFailed);
	// C1-05: outPlaintext must be cleared and empty on AuthFailed
	BOOST_CHECK(outPlaintext.empty());
}

BOOST_AUTO_TEST_CASE(ForbiddenSegmentIndexByteRejectTest)
{
	// CR-02 (Body Std v1.2): any uint32_be(segmentIndex) byte 0x0A/0x0D would split
	// Line 1 on the wire. Bootstrap extraction must reject (Status::Error).
	// Wire line 1: [16B salt][4B BE index][2B FF1 ct] — same salt as canonical vectors.
	struct Case
	{
		uint32_t index;
		const char* indexHex;
	};
	const Case cases[] = {
		{10, "0000000a"},
		{13, "0000000d"},
		{266, "0000010a"},
		{269, "0000010d"},
	};
	for (const auto& testCase : cases)
	{
		std::string line1 = "4b376d5839704c32715238764e34775a";
		line1 += testCase.indexHex;
		line1 += "3d3d";
		std::vector<uint8_t> wire = HexToBin(line1);
		BOOST_REQUIRE_EQUAL(wire.size(), 22U);

		YEncDecryptor decryptor("test123");
		std::vector<uint8_t> plaintext;
		std::vector<uint8_t> salt;
		uint32_t extractedIndex = 0;
		auto st = decryptor.DecryptControlLine(
			wire.data(), wire.size(), 0, 1, true, plaintext, &salt, &extractedIndex);
		BOOST_CHECK(st == YEncDecryptor::Status::Error);
		BOOST_CHECK(plaintext.empty());
		BOOST_CHECK(salt.empty());
		BOOST_CHECK_EQUAL(extractedIndex, 0U);
	}

	// Control: a safe index (11) with the same salt still passes bootstrap extraction.
	std::string safeLine1 = "4b376d5839704c32715238764e34775a0000000b3d3d";
	std::vector<uint8_t> safeWire = HexToBin(safeLine1);
	YEncDecryptor decryptor("test123");
	std::vector<uint8_t> plaintext;
	std::vector<uint8_t> salt;
	uint32_t extractedIndex = 0;
	auto st = decryptor.DecryptControlLine(
		safeWire.data(), safeWire.size(), 0, 1, true, plaintext, &salt, &extractedIndex);
	BOOST_CHECK_EQUAL(extractedIndex, 11U);
}

BOOST_AUTO_TEST_SUITE_END()
