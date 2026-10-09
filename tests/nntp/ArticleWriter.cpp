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
#include "ArticleWriter.h"
#include "DownloadInfo.h"
#include "Options.h"
#include "FileSystem.h"
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>

BOOST_AUTO_TEST_SUITE(NNTPTest)

BOOST_AUTO_TEST_CASE(ArticleWriterDirectWriteSuppressedWhenEncrypted)
{
	std::filesystem::path tempDir = std::filesystem::temp_directory_path() / "nzbget_test_writer_directwrite";
	CString errmsg;
	FileSystem::ForceDirectories(tempDir.string().c_str(), errmsg);

	std::unique_ptr<NzbInfo> nzbInfo = std::make_unique<NzbInfo>();
	nzbInfo->SetName("EncryptedRelease");
	nzbInfo->SetDestDir(tempDir.string().c_str());
	nzbInfo->SetYEncEncrypted(true);

	FileInfo fileInfo;
	fileInfo.SetFilename("payload.bin");
	fileInfo.SetNzbInfo(nzbInfo.get());
	fileInfo.SetForceDirectWrite(true);

	ArticleInfo articleInfo;
	articleInfo.SetPartNumber(1);
	articleInfo.SetSize(128);

	ArticleWriter writer;
	writer.SetFileInfo(&fileInfo);
	writer.SetArticleInfo(&articleInfo);
	writer.Prepare();

	BOOST_CHECK(writer.IsEncryptedRelease());

	// Start writer
	bool startOk = writer.Start(Decoder::efYenc, "payload.bin", 128, 0, 128);
	BOOST_REQUIRE(startOk);

	// Output file must NOT be initialized for direct write on encrypted release
	BOOST_CHECK_EQUAL(fileInfo.GetOutputInitialized(), false);
	BOOST_CHECK(writer.GetOutputFilename().empty());

	// Chunk writes via Write() must be suppressed (zero unauthenticated bytes committed)
	char cipherChunk[64];
	memset(cipherChunk, 0xAA, sizeof(cipherChunk));
	bool writeOk = writer.Write(cipherChunk, sizeof(cipherChunk));
	BOOST_CHECK(writeOk);

	// Verify temp file is empty or has zero bytes committed
	if (FileSystem::FileExists(writer.GetTempFilename().c_str()))
	{
		int64 size = FileSystem::FileSize(writer.GetTempFilename().c_str());
		BOOST_CHECK_EQUAL(size, 0);
	}

	writer.Finish(false);
	FileSystem::DeleteFile(writer.GetTempFilename().c_str());
	FileSystem::DeleteFile(writer.GetResultFilename().c_str());
}

BOOST_AUTO_TEST_CASE(ArticleWriterAuthenticatedDataCommit)
{
	std::filesystem::path tempDir = std::filesystem::temp_directory_path() / "nzbget_test_writer_commit";
	CString errmsg;
	FileSystem::ForceDirectories(tempDir.string().c_str(), errmsg);

	std::unique_ptr<NzbInfo> nzbInfo = std::make_unique<NzbInfo>();
	nzbInfo->SetName("CommitRelease");
	nzbInfo->SetDestDir(tempDir.string().c_str());
	nzbInfo->SetYEncEncrypted(true);

	FileInfo fileInfo;
	fileInfo.SetFilename("data.bin");
	fileInfo.SetNzbInfo(nzbInfo.get());

	ArticleInfo articleInfo;
	articleInfo.SetPartNumber(1);
	articleInfo.SetSize(32);

	ArticleWriter writer;
	writer.SetFileInfo(&fileInfo);
	writer.SetArticleInfo(&articleInfo);
	writer.Prepare();

	BOOST_REQUIRE(writer.Start(Decoder::efYenc, "data.bin", 32, 0, 32));

	// Chunk write of unauthenticated data is suppressed
	char dummyCipher[32];
	memset(dummyCipher, 0xCC, sizeof(dummyCipher));
	writer.Write(dummyCipher, 32);

	// Plaintext to commit after authentication
	std::string verifiedPlaintext = "PlaintextAuthenticatedContent123";
	BOOST_REQUIRE_EQUAL(verifiedPlaintext.size(), 32);

	bool commitOk = writer.CommitAuthenticatedData(verifiedPlaintext.data(), static_cast<int>(verifiedPlaintext.size()));
	BOOST_REQUIRE(commitOk);

	writer.Finish(true);

	// Verify result file exists and contains the verified plaintext exactly
	std::string resultPath = writer.GetResultFilename();
	BOOST_REQUIRE(FileSystem::FileExists(resultPath.c_str()));

	std::ifstream file(resultPath, std::ios::binary);
	std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	BOOST_CHECK_EQUAL(content, verifiedPlaintext);

	file.close();
	FileSystem::DeleteFile(resultPath.c_str());
}

BOOST_AUTO_TEST_CASE(ArticleWriterDiscardStagedDataZeroOutput)
{
	std::filesystem::path tempDir = std::filesystem::temp_directory_path() / "nzbget_test_writer_discard";
	CString errmsg;
	FileSystem::ForceDirectories(tempDir.string().c_str(), errmsg);

	std::unique_ptr<NzbInfo> nzbInfo = std::make_unique<NzbInfo>();
	nzbInfo->SetName("DiscardRelease");
	nzbInfo->SetDestDir(tempDir.string().c_str());
	nzbInfo->SetYEncEncrypted(true);

	FileInfo fileInfo;
	fileInfo.SetFilename("discard.bin");
	fileInfo.SetNzbInfo(nzbInfo.get());

	ArticleInfo articleInfo;
	articleInfo.SetPartNumber(1);
	articleInfo.SetSize(24);

	ArticleWriter writer;
	writer.SetFileInfo(&fileInfo);
	writer.SetArticleInfo(&articleInfo);
	writer.Prepare();

	BOOST_REQUIRE(writer.Start(Decoder::efYenc, "discard.bin", 24, 0, 24));

	// Commit staged data
	std::string stagedPlaintext = "TentativeStagedDataBytes";
	BOOST_REQUIRE(writer.CommitAuthenticatedData(stagedPlaintext.data(), static_cast<int>(stagedPlaintext.size())));

	std::string tempPath = writer.GetTempFilename();
	std::string resultPath = writer.GetResultFilename();

	// Temp file exists before discard
	BOOST_CHECK(FileSystem::FileExists(tempPath.c_str()));

	// Discard staged data (simulating Poly1305 authentication failure or abort)
	writer.DiscardStagedData();

	// Enforce Zero-Output Guarantee: no temp file or result file on disk
	BOOST_CHECK_EQUAL(FileSystem::FileExists(tempPath.c_str()), false);
	BOOST_CHECK_EQUAL(FileSystem::FileExists(resultPath.c_str()), false);
}

BOOST_AUTO_TEST_CASE(ArticleWriterUnencryptedReleasePreservesNormalBehavior)
{
	std::filesystem::path tempDir = std::filesystem::temp_directory_path() / "nzbget_test_writer_unencrypted";
	CString errmsg;
	FileSystem::ForceDirectories(tempDir.string().c_str(), errmsg);

	std::unique_ptr<NzbInfo> nzbInfo = std::make_unique<NzbInfo>();
	nzbInfo->SetName("UnencryptedRelease");
	nzbInfo->SetDestDir(tempDir.string().c_str());
	// Notice: *Unpack:YEncEncrypted is NOT set

	FileInfo fileInfo;
	fileInfo.SetFilename("normal.bin");
	fileInfo.SetNzbInfo(nzbInfo.get());

	ArticleInfo articleInfo;
	articleInfo.SetPartNumber(1);
	articleInfo.SetSize(16);

	ArticleWriter writer;
	writer.SetFileInfo(&fileInfo);
	writer.SetArticleInfo(&articleInfo);
	writer.Prepare();

	BOOST_CHECK_EQUAL(writer.IsEncryptedRelease(), false);

	BOOST_REQUIRE(writer.Start(Decoder::efYenc, "normal.bin", 16, 0, 16));

	// On unencrypted releases, Write() writes chunks directly
	char dataChunk[16] = "NormalPlainData";
	BOOST_CHECK(writer.Write(dataChunk, 15));

	writer.Finish(true);

	std::string outputPath = writer.GetOutputFilename();
	std::string resultPath = writer.GetResultFilename();
	bool outputExists = FileSystem::FileExists(outputPath.c_str());
	bool resultExists = FileSystem::FileExists(resultPath.c_str());
	BOOST_CHECK(outputExists || resultExists);

	if (outputExists) FileSystem::DeleteFile(outputPath.c_str());
	if (resultExists) FileSystem::DeleteFile(resultPath.c_str());
}

BOOST_AUTO_TEST_SUITE_END()
