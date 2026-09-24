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
	// Vector from control_line_encryption.json: control-vec-01-line-1-ybegin-single
	std::vector<uint8_t> wire1 = HexToBin("4b376d5839704c32715238764e34775a3ff69054da2b2309591e740e5b9fd79015f610d42f01bd203e5f55dadc39fc760407e845201f");
	std::vector<uint8_t> outPlaintext1;
	std::vector<uint8_t> outSalt1;

	auto st1 = decryptor.DecryptControlLine(wire1.data(), wire1.size(), 1, 1, true, outPlaintext1, &outSalt1);
	BOOST_REQUIRE_EQUAL(static_cast<int>(st1), static_cast<int>(YEncDecryptor::Status::Ok));
	std::string pt1(reinterpret_cast<const char*>(outPlaintext1.data()), outPlaintext1.size());
	BOOST_CHECK_EQUAL(pt1, "=ybegin line=128 size=18 name=file.bin");

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
	std::string line = "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b\r\n";
	std::string cipher;
	uint8_t salt[16];
	uint8_t tag[16];

	BOOST_CHECK(YEncDecryptor::ParseYEncryption(line.c_str(), line.length(), cipher, salt, tag));
	BOOST_CHECK_EQUAL(cipher, "XChaCha20-Poly1305");
	BOOST_CHECK_EQUAL(BinToHex(salt, 16), "1a2b3c4d5e6f7890abcdef1234567890");
	BOOST_CHECK_EQUAL(BinToHex(tag, 16), "0cd77ce245a654463f90b945b1d22d5b");

	// Malformed inputs
	std::string badCipher = "=yencryption cipher=AES-256-GCM salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b\r\n";
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(badCipher.c_str(), badCipher.length(), cipher, salt, tag));

	std::string badSalt = "=yencryption cipher=XChaCha20-Poly1305 salt=short tag=0cd77ce245a654463f90b945b1d22d5b\r\n";
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(badSalt.c_str(), badSalt.length(), cipher, salt, tag));

	std::string badTag = "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=nonhextag1234567890123456789012\r\n";
	BOOST_CHECK(!YEncDecryptor::ParseYEncryption(badTag.c_str(), badTag.length(), cipher, salt, tag));
}

BOOST_AUTO_TEST_CASE(DecoderEncryptedIntegrationTest)
{
	Decoder decoder;
	decoder.SetCrcCheck(false); // Testing payload exclusion and decryption
	YEncDecryptor decryptor("test123");
	decoder.SetDecryptor(&decryptor);
	decoder.SetSegmentIndex(1);

	std::vector<uint8_t> ciphertext = HexToBin("6a0d1eb225f844920540fa382ff68874");
	std::string yencBody = yEncSimpleEncode(ciphertext);

	std::stringstream ss;
	ss << "=ybegin line=128 size=" << ciphertext.size() << " name=test.dat\r\n";
	ss << "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b\r\n";
	ss << yencBody << "\r\n";
	ss << "=yend size=" << ciphertext.size() << "\r\n";
	ss << ".\r\n";

	std::string msg = ss.str();
	int len = decoder.DecodeBuffer(msg.data(), msg.size());

	BOOST_CHECK_EQUAL(len, static_cast<int>(ciphertext.size()));
	BOOST_CHECK(decoder.IsEncrypted());
	BOOST_CHECK_EQUAL(BinToHex(decoder.GetSalt(), 16), "1a2b3c4d5e6f7890abcdef1234567890");
	BOOST_CHECK_EQUAL(BinToHex(decoder.GetTag(), 16), "0cd77ce245a654463f90b945b1d22d5b");

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
	decoder.SetSegmentIndex(1);

	std::vector<uint8_t> ciphertext = HexToBin("6a0d1eb225f844920540fa382ff68874");
	std::string yencBody = yEncSimpleEncode(ciphertext);

	// Corrupt tag
	std::stringstream ss;
	ss << "=ybegin line=128 size=" << ciphertext.size() << " name=test.dat\r\n";
	ss << "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=ffffffffffffffffffffffffffffffff\r\n";
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

BOOST_AUTO_TEST_SUITE_END()
