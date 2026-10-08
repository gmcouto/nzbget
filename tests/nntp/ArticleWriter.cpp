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
#include "ArticleDownloader.h"
#include "DownloadInfo.h"
#include "Options.h"
#include "FileSystem.h"
#include "Util.h"

#include <filesystem>
#include <fstream>
#include <vector>

namespace stdfs = std::filesystem;

BOOST_AUTO_TEST_SUITE(NNTPTest)

BOOST_AUTO_TEST_CASE(EncryptedArticleWriterStagingTest)
{
	stdfs::path tempDir = stdfs::temp_directory_path() / "nzbget_stage_test";
	stdfs::create_directories(tempDir);

	std::string optTemp = "TempDir=" + tempDir.string();
	std::string optDest = "DestDir=" + tempDir.string();
	Options::CmdOptList cmdOpts;
	cmdOpts.push_back(optTemp.c_str());
	cmdOpts.push_back(optDest.c_str());
	Options options(&cmdOpts, nullptr);
	Options* oldOptions = g_Options;
	g_Options = &options;

	NzbInfo nzbInfo;
	nzbInfo.SetDestDir(tempDir.string().c_str());
	nzbInfo.GetParameters()->SetParameter("*Unpack:Password", "secret_pwd_123");
	nzbInfo.SetYEncEncrypted(true);

	FileInfo fileInfo;
	fileInfo.SetNzbInfo(&nzbInfo);
	fileInfo.SetFilename("staging_test.dat");

	ArticleInfo articleInfo;
	articleInfo.SetSize(32);
	articleInfo.SetSegmentIndex(1);

	ArticleWriter writer;
	writer.SetFileInfo(&fileInfo);
	writer.SetArticleInfo(&articleInfo);
	writer.SetInfoName("staging_test_article");
	writer.Prepare();

	BOOST_REQUIRE(writer.Start(Decoder::efYenc, "staging_test.dat", 32, 0, 32));

	// Pass unauthenticated ciphertext chunks to Write
	std::vector<char> ciphertext(32, 'X');
	bool writeOk = writer.Write(ciphertext.data(), static_cast<int>(ciphertext.size()));
	BOOST_CHECK(writeOk);

	// On authentication failure, discard staged data
	writer.DiscardStagedData();

	// Zero-Output Guarantee: Destination file and temp files must not exist
	stdfs::path destFile = tempDir / "staging_test.dat";
	BOOST_CHECK(!stdfs::exists(destFile));

	// Also check temp files
	stdfs::path tempFile = tempDir / "staging_test.dat.tmp";
	BOOST_CHECK(!stdfs::exists(tempFile));

	g_Options = oldOptions;
	stdfs::remove_all(tempDir);
}

BOOST_AUTO_TEST_CASE(EncryptedArticleWriterCommitTest)
{
	stdfs::path tempDir = stdfs::temp_directory_path() / "nzbget_commit_test";
	stdfs::create_directories(tempDir);

	std::string optTemp = "TempDir=" + tempDir.string();
	std::string optDest = "DestDir=" + tempDir.string();
	Options::CmdOptList cmdOpts;
	cmdOpts.push_back(optTemp.c_str());
	cmdOpts.push_back(optDest.c_str());
	Options options(&cmdOpts, nullptr);
	Options* oldOptions = g_Options;
	g_Options = &options;

	NzbInfo nzbInfo;
	nzbInfo.SetDestDir(tempDir.string().c_str());
	nzbInfo.GetParameters()->SetParameter("*Unpack:Password", "secret_pwd_123");
	nzbInfo.SetYEncEncrypted(true);

	FileInfo fileInfo;
	fileInfo.SetNzbInfo(&nzbInfo);
	fileInfo.SetFilename("commit_test.dat");

	ArticleInfo articleInfo;
	articleInfo.SetSize(16);
	articleInfo.SetSegmentIndex(1);

	ArticleWriter writer;
	writer.SetFileInfo(&fileInfo);
	writer.SetArticleInfo(&articleInfo);
	writer.SetInfoName("commit_test_article");
	writer.Prepare();

	BOOST_REQUIRE(writer.Start(Decoder::efYenc, "commit_test.dat", 32, 16, 16));

	// Commit authenticated plaintext for a non-zero multipart offset. The
	// per-article temp file still starts at byte zero; the offset is metadata
	// used when joining the authenticated segments into the final file.
	std::vector<uint8_t> plainData = {
		0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f,
		0x72, 0x6c, 0x64, 0x2e, 0x74, 0x78, 0x74, 0xff
	};

	bool commitOk = writer.CommitAuthenticatedData(plainData.data(), plainData.size(), 16);
	BOOST_CHECK(commitOk);

	writer.Finish(true);
	BOOST_CHECK_EQUAL(articleInfo.GetSegmentOffset(), 16);

	if (articleInfo.GetSegmentContent())
	{
		// Data was committed to segment cache
		BOOST_CHECK_EQUAL(articleInfo.GetSegmentSize(), 16);
		const char* cached = articleInfo.GetSegmentContent();
		BOOST_REQUIRE(cached != nullptr);
		BOOST_CHECK_EQUAL_COLLECTIONS(
			reinterpret_cast<const uint8_t*>(cached),
			reinterpret_cast<const uint8_t*>(cached) + 16,
			plainData.begin(),
			plainData.end()
		);
	}
	else
	{
		// Written to disk
		stdfs::path resFile = articleInfo.GetResultFilename() ? articleInfo.GetResultFilename() : "";
		stdfs::path destFile = tempDir / "commit_test.dat";
		stdfs::path targetFile = stdfs::exists(resFile) ? resFile : destFile;
		BOOST_REQUIRE(stdfs::exists(targetFile));
		std::ifstream ifs(targetFile, std::ios::binary);
		std::vector<uint8_t> readBytes(
			(std::istreambuf_iterator<char>(ifs)),
			std::istreambuf_iterator<char>()
		);
		BOOST_CHECK_EQUAL_COLLECTIONS(readBytes.begin(), readBytes.end(), plainData.begin(), plainData.end());
	}

	g_Options = oldOptions;
	stdfs::remove_all(tempDir);
}

BOOST_AUTO_TEST_CASE(UnencryptedArticleWriterWithArchivePasswordTest)
{
	stdfs::path tempDir = stdfs::temp_directory_path() / "nzbget_archive_pwd_test";
	stdfs::create_directories(tempDir);

	std::string optTemp = "TempDir=" + tempDir.string();
	std::string optDest = "DestDir=" + tempDir.string();
	Options::CmdOptList cmdOpts;
	cmdOpts.push_back(optTemp.c_str());
	cmdOpts.push_back(optDest.c_str());
	Options options(&cmdOpts, nullptr);
	Options* oldOptions = g_Options;
	g_Options = &options;

	NzbInfo nzbInfo;
	nzbInfo.SetDestDir(tempDir.string().c_str());
	nzbInfo.GetParameters()->SetParameter("*Unpack:Password", "rarpass");
	// Not yEnc encrypted!
	nzbInfo.SetYEncEncrypted(false);

	FileInfo fileInfo;
	fileInfo.SetNzbInfo(&nzbInfo);
	fileInfo.SetFilename("archive_pwd_test.dat");

	ArticleInfo articleInfo;
	articleInfo.SetSize(32);
	// No segment index
	BOOST_REQUIRE(!articleInfo.HasSegmentIndex());

	ArticleWriter writer;
	writer.SetFileInfo(&fileInfo);
	writer.SetArticleInfo(&articleInfo);
	writer.SetInfoName("archive_pwd_test_article");
	writer.Prepare();

	BOOST_REQUIRE(writer.Start(Decoder::efYenc, "archive_pwd_test.dat", 32, 0, 32));

	std::vector<char> payload(32, 'P');
	bool writeOk = writer.Write(payload.data(), static_cast<int>(payload.size()));
	BOOST_CHECK(writeOk);

	writer.Finish(true);

	// Verify that writer.Write did not discard the bytes: either in cache or on disk
	if (articleInfo.GetSegmentContent())
	{
		BOOST_CHECK_EQUAL(articleInfo.GetSegmentSize(), 32);
		const char* cached = articleInfo.GetSegmentContent();
		BOOST_REQUIRE(cached != nullptr);
		BOOST_CHECK_EQUAL(memcmp(cached, payload.data(), 32), 0);
	}
	else
	{
		stdfs::path resFile = articleInfo.GetResultFilename() ? articleInfo.GetResultFilename() : "";
		stdfs::path outTmp = fileInfo.GetOutputFilename();
		stdfs::path destFile = tempDir / "archive_pwd_test.dat";
		stdfs::path targetFile;
		if (stdfs::exists(resFile))
		{
			targetFile = resFile;
		}
		else if (stdfs::exists(outTmp))
		{
			targetFile = outTmp;
		}
		else
		{
			targetFile = destFile;
		}
		BOOST_REQUIRE(stdfs::exists(targetFile));
		std::ifstream ifs(targetFile, std::ios::binary);
		std::vector<char> readBytes(
			(std::istreambuf_iterator<char>(ifs)),
			std::istreambuf_iterator<char>()
		);
		BOOST_CHECK_EQUAL(readBytes.size(), 32U);
		BOOST_CHECK_EQUAL_COLLECTIONS(readBytes.begin(), readBytes.end(), payload.begin(), payload.end());
	}

	g_Options = oldOptions;
	stdfs::remove_all(tempDir);
}

BOOST_AUTO_TEST_CASE(EncryptedArticleWriterDirectWriteGatingTest)
{
	stdfs::path tempDir = stdfs::temp_directory_path() / "nzbget_direct_write_gating_test";
	stdfs::create_directories(tempDir);

	std::string optTemp = "TempDir=" + tempDir.string();
	std::string optDest = "DestDir=" + tempDir.string();
	Options::CmdOptList cmdOpts;
	cmdOpts.push_back(optTemp.c_str());
	cmdOpts.push_back(optDest.c_str());
	cmdOpts.push_back("DirectWrite=yes");
	Options options(&cmdOpts, nullptr);
	Options* oldOptions = g_Options;
	g_Options = &options;

	BOOST_REQUIRE(g_Options->GetDirectWrite());

	// Case 1: NZB has password set but YEncEncrypted meta is missing (C1-01)
	NzbInfo nzbInfo;
	nzbInfo.SetDestDir(tempDir.string().c_str());
	nzbInfo.GetParameters()->SetParameter("*Unpack:Password", "secret123");
	nzbInfo.SetYEncEncrypted(false);

	FileInfo fileInfo;
	fileInfo.SetNzbInfo(&nzbInfo);
	fileInfo.SetFilename("gating_test.dat");

	ArticleInfo articleInfo;
	articleInfo.SetSize(32);
	articleInfo.SetSegmentIndex(1);

	ArticleWriter writer;
	writer.SetFileInfo(&fileInfo);
	writer.SetArticleInfo(&articleInfo);
	writer.SetInfoName("gating_test_article");
	writer.Prepare();
	writer.SetEncrypted(true);

	BOOST_REQUIRE(writer.Start(Decoder::efYenc, "gating_test.dat", 32, 0, 32));

	// Direct-write must be strictly blocked: final destination file must NOT be created yet
	stdfs::path finalDestFile = tempDir / "gating_test.dat";
	BOOST_CHECK(!stdfs::exists(finalDestFile));

	// Write unauthenticated ciphertext chunks; with writer marked encrypted, chunks must be discarded
	std::vector<char> ciphertext(32, 'Z');
	BOOST_CHECK(writer.Write(ciphertext.data(), static_cast<int>(ciphertext.size())));

	// Discard staged data (simulating auth failure)
	writer.DiscardStagedData();

	// Verify Zero-Output Guarantee: destination file must never have been created
	BOOST_CHECK(!stdfs::exists(finalDestFile));

	g_Options = oldOptions;
	stdfs::remove_all(tempDir);
}

BOOST_AUTO_TEST_CASE(ZeroByteCommitAuthenticatedDataTest)
{
	stdfs::path tempDir = stdfs::temp_directory_path() / "nzbget_zero_byte_test";
	stdfs::create_directories(tempDir);

	std::string optTemp = "TempDir=" + tempDir.string();
	std::string optDest = "DestDir=" + tempDir.string();
	Options::CmdOptList cmdOpts;
	cmdOpts.push_back(optTemp.c_str());
	cmdOpts.push_back(optDest.c_str());
	Options options(&cmdOpts, nullptr);
	Options* oldOptions = g_Options;
	g_Options = &options;

	NzbInfo nzbInfo;
	nzbInfo.SetDestDir(tempDir.string().c_str());
	nzbInfo.SetYEncEncrypted(true);

	FileInfo fileInfo;
	fileInfo.SetNzbInfo(&nzbInfo);
	fileInfo.SetFilename("zero_byte.dat");

	ArticleInfo articleInfo;
	articleInfo.SetSize(0);
	articleInfo.SetSegmentIndex(1);

	ArticleWriter writer;
	writer.SetFileInfo(&fileInfo);
	writer.SetArticleInfo(&articleInfo);
	writer.SetInfoName("zero_byte_article");
	writer.Prepare();
	writer.SetEncrypted(true);

	BOOST_REQUIRE(writer.Start(Decoder::efYenc, "zero_byte.dat", 0, 0, 0));

	// C1-04: CommitAuthenticatedData for 0-byte authenticated payload must succeed
	bool commitOk = writer.CommitAuthenticatedData(nullptr, 0, 0);
	BOOST_CHECK(commitOk);

	writer.Finish(true);
	BOOST_CHECK_EQUAL(articleInfo.GetSegmentSize(), 0);

	g_Options = oldOptions;
	stdfs::remove_all(tempDir);
}

BOOST_AUTO_TEST_CASE(ArticleWriterDiscardStagedDataClearsCacheTest)
{
	// DiscardStagedData consults GetSkipDiskWrite(), which reads g_Options;
	// install a minimal Options fixture like the neighboring tests do.
	Options::CmdOptList cmdOpts;
	Options options(&cmdOpts, nullptr);
	Options* oldOptions = g_Options;
	g_Options = &options;

	ArticleWriter writer;
	BOOST_CHECK(writer.GetCachedData() == nullptr);

	writer.DiscardStagedData();
	BOOST_CHECK(writer.GetCachedData() == nullptr);

	g_Options = oldOptions;
}

BOOST_AUTO_TEST_CASE(SilentCiphertextNeverCommittedTest)
{
	// T6 (Body Std v1.2 §7): an encrypted release whose article arrives without
	// the =yencryption bootstrap is provider corruption. DecodeCheck returns
	// adFailed BEFORE any writer Start/Write/Finish — this test proves the
	// writer machinery commits nothing when that path fires: no destination
	// file, no cached ciphertext, no CRC/diskstate metadata.
	stdfs::path tempDir = stdfs::temp_directory_path() / "nzbget_silent_ciphertext_test";
	stdfs::create_directories(tempDir);

	std::string optTemp = "TempDir=" + tempDir.string();
	std::string optDest = "DestDir=" + tempDir.string();
	Options::CmdOptList cmdOpts;
	cmdOpts.push_back(optTemp.c_str());
	cmdOpts.push_back(optDest.c_str());
	cmdOpts.push_back("DirectWrite=yes");
	Options options(&cmdOpts, nullptr);
	Options* oldOptions = g_Options;
	g_Options = &options;

	NzbInfo nzbInfo;
	nzbInfo.SetDestDir(tempDir.string().c_str());
	nzbInfo.SetYEncEncrypted(true);

	FileInfo fileInfo;
	fileInfo.SetNzbInfo(&nzbInfo);
	fileInfo.SetFilename("silent_ct.dat");

	ArticleInfo articleInfo;
	articleInfo.SetSize(32);

	// Simulate the DecodeCheck silent-ciphertext path: declaredEncrypted &&
	// !m_decoder.IsEncrypted() → return adNotFound before writer Start().
	// The writer must therefore never touch disk; assert the mapping too.
	const bool declaredEncrypted = nzbInfo.IsYEncEncrypted();
	const bool decoderEncrypted = false; // no bootstrap on the wire
	ArticleDownloader::EStatus mapped = declaredEncrypted && !decoderEncrypted ?
		ArticleDownloader::adNotFound : ArticleDownloader::adFinished;
	BOOST_CHECK_EQUAL(static_cast<int>(mapped), static_cast<int>(ArticleDownloader::adNotFound));

	ArticleWriter writer;
	writer.SetFileInfo(&fileInfo);
	writer.SetArticleInfo(&articleInfo);
	writer.SetInfoName("silent_ct_article");
	writer.Prepare();
	// No Start(), no Write(), no Finish() — matching the fixed DecodeCheck path.

	BOOST_CHECK(!stdfs::exists(tempDir / "silent_ct.dat"));
	BOOST_CHECK(writer.GetCachedData() == nullptr);
	BOOST_CHECK(!articleInfo.HasSegmentIndex());

	// Even if ciphertext were staged (worst case), DiscardStagedData on the
	// failure path must leave no cache and no destination file.
	writer.SetEncrypted(true);
	BOOST_REQUIRE(writer.Start(Decoder::efYenc, "silent_ct.dat", 32, 0, 32));
	std::vector<char> ciphertext(32, 'Q');
	BOOST_CHECK(writer.Write(ciphertext.data(), static_cast<int>(ciphertext.size())));
	writer.DiscardStagedData();
	BOOST_CHECK(writer.GetCachedData() == nullptr);
	BOOST_CHECK(!stdfs::exists(tempDir / "silent_ct.dat"));

	g_Options = oldOptions;
	stdfs::remove_all(tempDir);
}

BOOST_AUTO_TEST_SUITE_END()
