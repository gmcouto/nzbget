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
#include "ArticleDownloader.h"
#include "DownloadInfo.h"
#include "Options.h"
#include "FileSystem.h"
#include "YEncDecryptor.h"
#include "Util.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <vector>

namespace {

std::string LocalYEncEncode(const std::string& data)
{
	std::string encodedData = "";
	for (unsigned char c : data)
	{
		encodedData += static_cast<unsigned char>((c + 42) % 256);
	}
	return encodedData;
}

std::vector<uint8_t> LocalHexToBytes(const std::string& hex)
{
	std::vector<uint8_t> bytes;
	bytes.reserve(hex.size() / 2);
	for (size_t i = 0; i < hex.size(); i += 2)
	{
		unsigned int byteVal;
		std::stringstream ss;
		ss << std::hex << hex.substr(i, 2);
		ss >> byteVal;
		bytes.push_back(static_cast<uint8_t>(byteVal));
	}
	return bytes;
}

std::string BuildEncryptedWireArticle(
	const std::string& password,
	const std::vector<uint8_t>& salt,
	uint32_t segmentIndex,
	const std::vector<uint8_t>& ct,
	const std::vector<uint8_t>& tag,
	const std::string& filename = "test.dat")
{
	YEncDecryptor encDec(password);

	std::stringstream line1Ss;
	line1Ss << "=ybegin line=128 size=" << ct.size() << " name=" << filename;
	std::string line1Plain = line1Ss.str();

	std::vector<uint8_t> wireLine1;
	encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line1Plain.data()), line1Plain.size(),
		segmentIndex, 1, true, salt.data(), wireLine1
	);

	// Hex encode tag & salt
	std::stringstream saltHexSs;
	for (uint8_t b : salt) { saltHexSs << std::hex << std::setw(2) << std::setfill('0') << (int)b; }
	std::stringstream tagHexSs;
	for (uint8_t b : tag) { tagHexSs << std::hex << std::setw(2) << std::setfill('0') << (int)b; }

	std::stringstream line2Ss;
	line2Ss << "=yencryption cipher=XChaCha20-Poly1305 salt=" << saltHexSs.str()
			<< " index=" << std::hex << std::setw(8) << std::setfill('0') << segmentIndex
			<< " tag=" << tagHexSs.str();
	std::string line2Plain = line2Ss.str();

	std::vector<uint8_t> wireLine2;
	encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line2Plain.data()), line2Plain.size(),
		segmentIndex, 2, false, salt.data(), wireLine2
	);

	std::string wireLine3 = LocalYEncEncode(std::string(reinterpret_cast<const char*>(ct.data()), ct.size()));

	Crc32 crc;
	crc.Append((uchar*)ct.data(), (uint32)ct.size());
	uint32_t ctCrc = crc.Finish();

	std::stringstream line4Ss;
	line4Ss << "=yend size=" << ct.size() << " crc32=" << std::hex << std::setw(8) << std::setfill('0') << ctCrc;
	std::string line4Plain = line4Ss.str();

	std::vector<uint8_t> wireLine4;
	encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line4Plain.data()), line4Plain.size(),
		segmentIndex, 4, false, salt.data(), wireLine4
	);

	std::string fullWire;
	fullWire.append(reinterpret_cast<const char*>(wireLine1.data()), wireLine1.size());
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine2.data()), wireLine2.size());
	fullWire.append("\r\n");
	fullWire.append(wireLine3);
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine4.data()), wireLine4.size());
	fullWire.append("\r\n.\r\n");

	return fullWire;
}

} // namespace

BOOST_AUTO_TEST_SUITE(NNTPTest)

BOOST_AUTO_TEST_CASE(ArticleDownloaderEncryptedReleaseInitializesDecryptor)
{
	std::unique_ptr<NzbInfo> nzbInfo = std::make_unique<NzbInfo>();
	nzbInfo->SetName("ReleaseWithPassword");
	nzbInfo->SetYEncEncrypted(true);
	nzbInfo->GetParameters()->SetParameter("*Unpack:Password", "canary_password_xyz");

	FileInfo fileInfo;
	fileInfo.SetFilename("secret.bin");
	fileInfo.SetNzbInfo(nzbInfo.get());

	ArticleInfo articleInfo;
	articleInfo.SetPartNumber(1);
	articleInfo.SetSize(64);

	ArticleDownloader downloader;
	downloader.SetFileInfo(&fileInfo);
	downloader.SetArticleInfo(&articleInfo);

	// Ensure decryptor can be attached and initialized with release password
	auto decryptor = std::make_unique<YEncDecryptor>(nzbInfo->GetPassword());
	downloader.SetDecryptor(std::move(decryptor));
	downloader.GetDecoder()->SetDecryptor(downloader.GetDecryptor());

	BOOST_CHECK(downloader.GetDecryptor() != nullptr);
	BOOST_CHECK_EQUAL(downloader.GetDecryptor()->GetPassword(), "canary_password_xyz");
	BOOST_CHECK(downloader.GetArticleWriter()->IsEncryptedRelease());
}

BOOST_AUTO_TEST_CASE(ArticleDownloaderDecodeCheckAuthenticatedSuccess)
{
	std::filesystem::path tempDir = std::filesystem::temp_directory_path() / "nzbget_test_dl_success";
	CString errmsg;
	FileSystem::ForceDirectories(tempDir.string().c_str(), errmsg);

	std::string password = "test123";
	std::vector<uint8_t> salt = LocalHexToBytes("1a2b3c4d5e6f7890abcdef1234567890");
	std::vector<uint8_t> ct = LocalHexToBytes("6a0d1eb225f844920540fa382ff68874");
	std::vector<uint8_t> tag = LocalHexToBytes("0cd77ce245a654463f90b945b1d22d5b");
	std::vector<uint8_t> expectedPlain = LocalHexToBytes("48656c6c6f20576f726c642e747874ff");
	uint32_t segmentIndex = 1;

	std::string wireMsg = BuildEncryptedWireArticle(password, salt, segmentIndex, ct, tag, "test.dat");

	std::unique_ptr<NzbInfo> nzbInfo = std::make_unique<NzbInfo>();
	nzbInfo->SetName("AuthSuccessRelease");
	nzbInfo->SetDestDir(tempDir.string().c_str());
	nzbInfo->SetYEncEncrypted(true);
	nzbInfo->GetParameters()->SetParameter("*Unpack:Password", password.c_str());

	FileInfo fileInfo;
	fileInfo.SetFilename("test.dat");
	fileInfo.SetNzbInfo(nzbInfo.get());

	ArticleInfo articleInfo;
	articleInfo.SetPartNumber(1);
	articleInfo.SetSize(16);
	articleInfo.SetCrc(0);

	ArticleDownloader downloader;
	downloader.SetFileInfo(&fileInfo);
	downloader.SetArticleInfo(&articleInfo);

	auto decryptor = std::make_unique<YEncDecryptor>(password);
	downloader.SetDecryptor(std::move(decryptor));
	downloader.GetDecoder()->SetDecryptor(downloader.GetDecryptor());
	downloader.GetDecoder()->SetPassword(password.c_str());
	downloader.GetDecoder()->SetCrcCheck(true);

	downloader.GetArticleWriter()->SetFileInfo(&fileInfo);
	downloader.GetArticleWriter()->SetArticleInfo(&articleInfo);
	downloader.GetArticleWriter()->Prepare();

	// Feed wire message into decoder
	downloader.GetDecoder()->DecodeBuffer(wireMsg.data(), static_cast<int>(wireMsg.size()));

	// Verify Decoder finished successfully
	BOOST_CHECK_EQUAL(static_cast<int>(downloader.GetDecoder()->Check()), static_cast<int>(Decoder::dsFinished));
	BOOST_CHECK(downloader.GetDecoder()->IsEncrypted());

	// Run DecodeCheck()
	ArticleDownloader::EStatus status = downloader.DecodeCheck();
	BOOST_CHECK_EQUAL(static_cast<int>(status), static_cast<int>(ArticleDownloader::adFinished));

	// Verify ciphertext CRC was NOT set on articleInfo (CRC calculation left for ParChecker on plaintext)
	BOOST_CHECK_EQUAL(articleInfo.GetCrc(), 0);

	// Finish writer and verify plaintext committed to disk
	downloader.GetArticleWriter()->Finish(true);
	std::string resultPath = downloader.GetArticleWriter()->GetResultFilename();
	BOOST_REQUIRE(FileSystem::FileExists(resultPath.c_str()));

	std::ifstream file(resultPath, std::ios::binary);
	std::vector<uint8_t> diskPlain((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	BOOST_CHECK_EQUAL_COLLECTIONS(diskPlain.begin(), diskPlain.end(), expectedPlain.begin(), expectedPlain.end());

	file.close();
	FileSystem::DeleteFile(resultPath.c_str());
}

BOOST_AUTO_TEST_CASE(ArticleDownloaderDecodeCheckAuthFailedDiscardsDataAndReturnsNotFound)
{
	std::filesystem::path tempDir = std::filesystem::temp_directory_path() / "nzbget_test_dl_failover";
	CString errmsg;
	FileSystem::ForceDirectories(tempDir.string().c_str(), errmsg);

	std::string password = "test123";
	std::vector<uint8_t> salt = LocalHexToBytes("1a2b3c4d5e6f7890abcdef1234567890");
	std::vector<uint8_t> ct = LocalHexToBytes("6a0d1eb225f844920540fa382ff68874");
	// Corrupt the authentication tag
	std::vector<uint8_t> corruptTag = LocalHexToBytes("0cd77ce245a654463f90b945b1d22d00");
	uint32_t segmentIndex = 1;

	std::string wireMsg = BuildEncryptedWireArticle(password, salt, segmentIndex, ct, corruptTag, "corrupt.dat");

	std::unique_ptr<NzbInfo> nzbInfo = std::make_unique<NzbInfo>();
	nzbInfo->SetName("AuthFailRelease");
	nzbInfo->SetDestDir(tempDir.string().c_str());
	nzbInfo->SetYEncEncrypted(true);
	nzbInfo->GetParameters()->SetParameter("*Unpack:Password", password.c_str());

	FileInfo fileInfo;
	fileInfo.SetFilename("corrupt.dat");
	fileInfo.SetNzbInfo(nzbInfo.get());

	ArticleInfo articleInfo;
	articleInfo.SetPartNumber(1);
	articleInfo.SetSize(16);

	ArticleDownloader downloader;
	downloader.SetFileInfo(&fileInfo);
	downloader.SetArticleInfo(&articleInfo);

	auto decryptor = std::make_unique<YEncDecryptor>(password);
	downloader.SetDecryptor(std::move(decryptor));
	downloader.GetDecoder()->SetDecryptor(downloader.GetDecryptor());
	downloader.GetDecoder()->SetPassword(password.c_str());
	downloader.GetDecoder()->SetCrcCheck(true);

	downloader.GetArticleWriter()->SetFileInfo(&fileInfo);
	downloader.GetArticleWriter()->SetArticleInfo(&articleInfo);
	downloader.GetArticleWriter()->Prepare();

	// Feed corrupted wire message
	downloader.GetDecoder()->DecodeBuffer(wireMsg.data(), static_cast<int>(wireMsg.size()));

	// Check() should detect auth failure
	BOOST_CHECK_EQUAL(static_cast<int>(downloader.GetDecoder()->Check()), static_cast<int>(Decoder::dsAuthFailed));

	// DecodeCheck() must return adNotFound (triggering provider failover without exhausting retries)
	ArticleDownloader::EStatus status = downloader.DecodeCheck();
	BOOST_CHECK_EQUAL(static_cast<int>(status), static_cast<int>(ArticleDownloader::adNotFound));

	// Zero-Output Guarantee: verify no temp or result file remains on disk
	std::string tempPath = downloader.GetArticleWriter()->GetTempFilename();
	std::string resultPath = downloader.GetArticleWriter()->GetResultFilename();
	BOOST_CHECK_EQUAL(FileSystem::FileExists(tempPath.c_str()), false);
	BOOST_CHECK_EQUAL(FileSystem::FileExists(resultPath.c_str()), false);
}

BOOST_AUTO_TEST_CASE(EncryptedProviderSecretLoggingAuditTest)
{
	// Test validating that passwords and plaintext strings are never emitted in logs.
	// Canaries checked by test_secret_logging_audit.py:
	const std::string canaryPassword = "SuperSecretAuditPassword999";
	const std::string canaryPlaintext = "SecretPlaintextStringXYZ";

	std::filesystem::path tempDir = std::filesystem::temp_directory_path() / "nzbget_test_audit_canary";
	CString errmsg;
	FileSystem::ForceDirectories(tempDir.string().c_str(), errmsg);

	std::vector<uint8_t> salt = LocalHexToBytes("1a2b3c4d5e6f7890abcdef1234567890");
	std::vector<uint8_t> ct = LocalHexToBytes("6a0d1eb225f844920540fa382ff68874");
	// Corrupt tag to force auth failure
	std::vector<uint8_t> corruptTag = LocalHexToBytes("0cd77ce245a654463f90b945b1d22d00");
	uint32_t segmentIndex = 1;

	std::string wireMsg = BuildEncryptedWireArticle(canaryPassword, salt, segmentIndex, ct, corruptTag, "audit.dat");

	std::unique_ptr<NzbInfo> nzbInfo = std::make_unique<NzbInfo>();
	nzbInfo->SetName("AuditRelease");
	nzbInfo->SetDestDir(tempDir.string().c_str());
	nzbInfo->SetYEncEncrypted(true);
	nzbInfo->GetParameters()->SetParameter("*Unpack:Password", canaryPassword.c_str());

	FileInfo fileInfo;
	fileInfo.SetFilename("audit.dat");
	fileInfo.SetNzbInfo(nzbInfo.get());

	ArticleInfo articleInfo;
	articleInfo.SetPartNumber(1);
	articleInfo.SetSize(16);

	ArticleDownloader downloader;
	downloader.SetFileInfo(&fileInfo);
	downloader.SetArticleInfo(&articleInfo);

	auto decryptor = std::make_unique<YEncDecryptor>(canaryPassword);
	downloader.SetDecryptor(std::move(decryptor));
	downloader.GetDecoder()->SetDecryptor(downloader.GetDecryptor());
	downloader.GetDecoder()->SetPassword(canaryPassword.c_str());
	downloader.GetDecoder()->SetCrcCheck(true);

	downloader.GetArticleWriter()->SetFileInfo(&fileInfo);
	downloader.GetArticleWriter()->SetArticleInfo(&articleInfo);
	downloader.GetArticleWriter()->Prepare();

	downloader.GetDecoder()->DecodeBuffer(wireMsg.data(), static_cast<int>(wireMsg.size()));
	BOOST_CHECK_EQUAL(static_cast<int>(downloader.GetDecoder()->Check()), static_cast<int>(Decoder::dsAuthFailed));

	// Trigger logging on auth failure
	ArticleDownloader::EStatus status = downloader.DecodeCheck();
	BOOST_CHECK_EQUAL(static_cast<int>(status), static_cast<int>(ArticleDownloader::adNotFound));

	// Ensure paths do not leak secrets
	bool passLeak = downloader.GetArticleWriter()->GetTempFilename().find(canaryPassword) != std::string::npos;
	BOOST_CHECK(!passLeak);
	bool plainLeak = downloader.GetArticleWriter()->GetTempFilename().find(canaryPlaintext) != std::string::npos;
	BOOST_CHECK(!plainLeak);
}

BOOST_AUTO_TEST_SUITE_END()
