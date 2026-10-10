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
#include <fstream>
#include "Options.h"
#include "DownloadInfo.h"
#include "DiskState.h"
#include "FileSystem.h"

BOOST_AUTO_TEST_SUITE(QueueTest)

namespace
{
struct ScopedQueueDir
{
	fs::path m_tempPath;
	Options::CmdOptList m_cmdOpts;
	std::unique_ptr<Options> m_options;
	Options* m_oldOptions;

	ScopedQueueDir(const std::string& tag)
	{
		m_tempPath = fs::temp_directory_path() / ("nzbget_test_diskstate_" + tag);
		std::error_code ec;
		fs::remove_all(m_tempPath, ec);
		fs::create_directories(m_tempPath, ec);

		std::string queueOpt = "QueueDir=" + m_tempPath.string();
		m_cmdOpts.push_back(queueOpt.c_str());
		m_options = std::make_unique<Options>(&m_cmdOpts, nullptr);

		m_oldOptions = g_Options;
		g_Options = m_options.get();
	}

	~ScopedQueueDir()
	{
		g_Options = m_oldOptions;
		m_options.reset();
		std::error_code ec;
		fs::remove_all(m_tempPath, ec);
	}

	void WriteFile(int fileId, const std::string& content) const
	{
		fs::path filePath = m_tempPath / std::to_string(fileId);
		std::ofstream ofs(filePath, std::ios::binary);
		ofs << content;
		ofs.close();
	}
};
}

BOOST_AUTO_TEST_CASE(DiskStateSegmentIdentityTest)
{
	ScopedQueueDir queueDir("roundtrip");

	FileInfo fileInfo(101);
	fileInfo.SetSubject("[2/5] - \"testfile.bin\" yEnc (1/2)");
	fileInfo.SetFilename("testfile.bin");

	auto art1 = std::make_unique<ArticleInfo>();
	art1->SetPartNumber(1);
	art1->SetSize(1000);
	art1->SetMessageId("art1@test.com");
	art1->SetSegmentIndex(10);
	fileInfo.GetArticles()->push_back(std::move(art1));

	auto art2 = std::make_unique<ArticleInfo>();
	art2->SetPartNumber(2);
	art2->SetSize(1200);
	art2->SetMessageId("art2@test.com");
	art2->SetSegmentIndex(11);
	fileInfo.GetArticles()->push_back(std::move(art2));

	BOOST_REQUIRE(g_DiskState->SaveFile(&fileInfo));

	FileInfo loaded(101);
	BOOST_REQUIRE(g_DiskState->LoadFile(&loaded, true, true));

	BOOST_REQUIRE_EQUAL(loaded.GetArticles()->size(), 2U);

	ArticleInfo* loadedArt1 = loaded.GetArticles()->at(0).get();
	BOOST_CHECK_EQUAL(loadedArt1->GetPartNumber(), 1);
	BOOST_CHECK_EQUAL(loadedArt1->GetSize(), 1000);
	BOOST_CHECK_EQUAL(std::string(loadedArt1->GetMessageId()), "art1@test.com");
	BOOST_CHECK(loadedArt1->HasSegmentIndex());
	if (loadedArt1->HasSegmentIndex())
	{
		BOOST_CHECK_EQUAL(loadedArt1->GetSegmentIndex().value(), 10U);
	}

	ArticleInfo* loadedArt2 = loaded.GetArticles()->at(1).get();
	BOOST_CHECK_EQUAL(loadedArt2->GetPartNumber(), 2);
	BOOST_CHECK_EQUAL(loadedArt2->GetSize(), 1200);
	BOOST_CHECK_EQUAL(std::string(loadedArt2->GetMessageId()), "art2@test.com");
	BOOST_CHECK(loadedArt2->HasSegmentIndex());
	if (loadedArt2->HasSegmentIndex())
	{
		BOOST_CHECK_EQUAL(loadedArt2->GetSegmentIndex().value(), 11U);
	}
}

BOOST_AUTO_TEST_CASE(DiskStateIdempotentRestartTest)
{
	ScopedQueueDir queueDir("idempotent");

	FileInfo origFile(102);
	origFile.SetSubject("[3/7] - \"movie.part03.rar\" yEnc (1/3)");
	origFile.SetFilename("movie.part03.rar");

	for (int part = 1; part <= 3; ++part)
	{
		auto art = std::make_unique<ArticleInfo>();
		art->SetPartNumber(part);
		art->SetSize(500000 + part * 100);
		art->SetMessageId(BString<100>("msg_%i@test.com", part));
		art->SetSegmentIndex(25 + part - 1);
		origFile.GetArticles()->push_back(std::move(art));
	}

	// First cycle: Save -> Load
	BOOST_REQUIRE(g_DiskState->SaveFile(&origFile));

	FileInfo load1(102);
	BOOST_REQUIRE(g_DiskState->LoadFile(&load1, true, true));

	BOOST_REQUIRE_EQUAL(load1.GetArticles()->size(), 3U);
	for (size_t i = 0; i < 3; ++i)
	{
		BOOST_CHECK_EQUAL(load1.GetArticles()->at(i)->GetPartNumber(), (int)(i + 1));
		BOOST_CHECK_EQUAL(load1.GetArticles()->at(i)->GetSegmentIndex().value(), (uint32)(25 + i));
	}

	// Second cycle: Save -> Load (idempotent restart)
	BOOST_REQUIRE(g_DiskState->SaveFile(&load1));

	FileInfo load2(102);
	BOOST_REQUIRE(g_DiskState->LoadFile(&load2, true, true));

	BOOST_REQUIRE_EQUAL(load2.GetArticles()->size(), 3U);
	for (size_t i = 0; i < 3; ++i)
	{
		BOOST_CHECK_EQUAL(load2.GetArticles()->at(i)->GetPartNumber(), (int)(i + 1));
		BOOST_CHECK_EQUAL(load2.GetArticles()->at(i)->GetSegmentIndex().value(), (uint32)(25 + i));
	}

	// Test two-phase loading: file summary first, articles later (LoadArticles)
	FileInfo loadSummaryOnly(102);
	BOOST_REQUIRE(g_DiskState->LoadFile(&loadSummaryOnly, true, false));
	BOOST_CHECK_EQUAL(loadSummaryOnly.GetArticles()->size(), 0U);

	BOOST_REQUIRE(g_DiskState->LoadArticles(&loadSummaryOnly));
	BOOST_REQUIRE_EQUAL(loadSummaryOnly.GetArticles()->size(), 3U);
	for (size_t i = 0; i < 3; ++i)
	{
		BOOST_CHECK_EQUAL(loadSummaryOnly.GetArticles()->at(i)->GetPartNumber(), (int)(i + 1));
		BOOST_CHECK_EQUAL(loadSummaryOnly.GetArticles()->at(i)->GetSegmentIndex().value(), (uint32)(25 + i));
	}
}

BOOST_AUTO_TEST_CASE(DiskStateVersion7DowngradeCompatibilityTest)
{
	ScopedQueueDir queueDir("v7compat");

	// Hand-authored version-7 diskstate file fixture (no segmentIndex)
	const std::string v7Content =
		"nzbget diskstate file version 7\n"
		"[1/2] - \"v7file.bin\" yEnc (1/2)\n"
		"v7file.bin\n"
		"v7file.bin\n"
		"v7file.bin\n"
		"1,12345678\n"
		"0,2500\n"
		"0,0\n"
		"0\n"
		"2,0\n"
		"1\n"
		"alt.binaries.test\n"
		"2\n"
		"1,1000\n"
		"art1@v7.com\n"
		"2,1500\n"
		"art2@v7.com\n";

	queueDir.WriteFile(201, v7Content);

	FileInfo loadedV7(201);
	BOOST_REQUIRE(g_DiskState->LoadFile(&loadedV7, true, true));

	BOOST_CHECK_EQUAL(std::string(loadedV7.GetFilename()), "v7file.bin");
	BOOST_CHECK_EQUAL(std::string(loadedV7.GetSubject()), "[1/2] - \"v7file.bin\" yEnc (1/2)");
	BOOST_CHECK_EQUAL(loadedV7.GetSize(), 2500);

	BOOST_REQUIRE_EQUAL(loadedV7.GetArticles()->size(), 2U);

	ArticleInfo* art1 = loadedV7.GetArticles()->at(0).get();
	BOOST_CHECK_EQUAL(art1->GetPartNumber(), 1);
	BOOST_CHECK_EQUAL(art1->GetSize(), 1000);
	BOOST_CHECK_EQUAL(std::string(art1->GetMessageId()), "art1@v7.com");
	BOOST_CHECK(!art1->HasSegmentIndex());

	ArticleInfo* art2 = loadedV7.GetArticles()->at(1).get();
	BOOST_CHECK_EQUAL(art2->GetPartNumber(), 2);
	BOOST_CHECK_EQUAL(art2->GetSize(), 1500);
	BOOST_CHECK_EQUAL(std::string(art2->GetMessageId()), "art2@v7.com");
	BOOST_CHECK(!art2->HasSegmentIndex());
}

BOOST_AUTO_TEST_CASE(DiskStateVersion8OrdinaryUnencryptedRoundtripTest)
{
	ScopedQueueDir queueDir("v8ordinary");

	// An ordinary unencrypted file in version 8 has no segmentIndex on its articles
	FileInfo fileInfo(301);
	fileInfo.SetSubject("Ordinary File Subject yEnc (1/2)");
	fileInfo.SetFilename("ordinary.bin");

	auto art1 = std::make_unique<ArticleInfo>();
	art1->SetPartNumber(1);
	art1->SetSize(800);
	art1->SetMessageId("art1@ordinary.com");
	fileInfo.GetArticles()->push_back(std::move(art1));

	auto art2 = std::make_unique<ArticleInfo>();
	art2->SetPartNumber(2);
	art2->SetSize(900);
	art2->SetMessageId("art2@ordinary.com");
	fileInfo.GetArticles()->push_back(std::move(art2));

	BOOST_REQUIRE(g_DiskState->SaveFile(&fileInfo));

	// Verify the article line on disk carries segmentIndex 0 (not yet known)
	fs::path savedPath = queueDir.m_tempPath / "301";
	std::ifstream ifs(savedPath);
	std::string line;
	bool foundArticle1 = false;
	while (std::getline(ifs, line))
	{
		if (line == "1,800,0")
		{
			foundArticle1 = true;
		}
	}
	BOOST_CHECK(foundArticle1);

	// Load and verify fields are unset
	FileInfo loaded(301);
	BOOST_REQUIRE(g_DiskState->LoadFile(&loaded, true, true));

	BOOST_REQUIRE_EQUAL(loaded.GetArticles()->size(), 2U);
	BOOST_CHECK(!loaded.GetArticles()->at(0)->HasSegmentIndex());
	BOOST_CHECK(!loaded.GetArticles()->at(1)->HasSegmentIndex());
	BOOST_CHECK_EQUAL(loaded.GetArticles()->at(0)->GetPartNumber(), 1);
	BOOST_CHECK_EQUAL(loaded.GetArticles()->at(1)->GetPartNumber(), 2);
}

BOOST_AUTO_TEST_CASE(DiskStateMalformedAndCorruptTest)
{
	ScopedQueueDir queueDir("corrupt");

	auto createTemplate = [](const std::string& art1Line, const std::string& art2Line)
	{
		return std::string("nzbget diskstate file version 8\n") +
			"Test Subject\n" +
			"corrupt.bin\n" +
			"corrupt.bin\n" +
			"corrupt.bin\n" +
			"1,12345678\n" +
			"0,2000\n" +
			"0,0\n" +
			"0\n" +
			"2,0\n" +
			"1\n" +
			"alt.binaries.test\n" +
			"2\n" +
			art1Line + "\n" +
			"art1@corrupt.com\n" +
			art2Line + "\n" +
			"art2@corrupt.com\n";
	};

	int testId = 400;

	auto checkFails = [&](const std::string& content)
	{
		++testId;
		queueDir.WriteFile(testId, content);
		FileInfo loaded(testId);
		bool success = g_DiskState->LoadFile(&loaded, true, true);
		BOOST_CHECK_MESSAGE(!success, "Expected load failure for fileId " + std::to_string(testId));
	};

	// 1. Article missing segmentIndex in version 8 (only part,size)
	checkFails(createTemplate("1,1000", "2,1000,11"));

	// 2. Article with negative segmentIndex
	checkFails(createTemplate("1,1000,-1", "2,1000,11"));

	// 3. Article with segmentIndex 0 is allowed (index not yet extracted)
	{
		++testId;
		queueDir.WriteFile(testId, createTemplate("1,1000,0", "2,1000,11"));
		FileInfo loaded(testId);
		bool success = g_DiskState->LoadFile(&loaded, true, true);
		BOOST_CHECK(success);
		BOOST_REQUIRE_EQUAL(loaded.GetArticles()->size(), 2U);
		BOOST_CHECK(!loaded.GetArticles()->at(0)->HasSegmentIndex());
		BOOST_REQUIRE(loaded.GetArticles()->at(1)->HasSegmentIndex());
		BOOST_CHECK_EQUAL(loaded.GetArticles()->at(1)->GetSegmentIndex().value(), 11U);
	}

	// 4. Article with declared part number 0
	checkFails(createTemplate("0,1000,10", "2,1000,11"));

	// 5. Truncated file before articles section completes
	std::string truncated =
		"nzbget diskstate file version 8\n"
		"Test Subject\n"
		"corrupt.bin\n"
		"corrupt.bin\n"
		"corrupt.bin\n"
		"0,0\n";
	checkFails(truncated);

	// 6. Invalid format version 0
	std::string v0Content =
		"nzbget diskstate file version 0\n"
		"Test Subject\n"
		"corrupt.bin\n";
	checkFails(v0Content);

	// 7. Missing or invalid signature
	std::string badSig =
		"bad signature file version 8\n"
		"Test Subject\n";
	checkFails(badSig);
}

BOOST_AUTO_TEST_CASE(DiskStateObfuscatedSegmentIdentityTest)
{
	ScopedQueueDir queueDir("obfuscated");

	FileInfo origFile(501);
	origFile.SetSubject("7a8b9c0d1e2f3a4b");
	origFile.SetFilename("obfuscated.bin");
	origFile.SetOrigname("obfuscated.bin");

	std::unique_ptr<ArticleInfo> art = std::make_unique<ArticleInfo>();
	art->SetPartNumber(1);
	art->SetSize(1000);
	art->SetMessageId("art1@obfuscated.com");
	art->SetSegmentIndex(42);
	origFile.GetArticles()->push_back(std::move(art));

	BOOST_REQUIRE(g_DiskState->SaveFile(&origFile));

	// Reload and verify the bootstrap-extracted article segmentIndex 42 survives
	FileInfo loadedFile(501);
	BOOST_REQUIRE(g_DiskState->LoadFile(&loadedFile, true, true));

	BOOST_REQUIRE_EQUAL(loadedFile.GetArticles()->size(), 1U);
	BOOST_REQUIRE(loadedFile.GetArticles()->front()->HasSegmentIndex());
	BOOST_CHECK_EQUAL(loadedFile.GetArticles()->front()->GetSegmentIndex().value(), 42U);
}

BOOST_AUTO_TEST_CASE(DiskStateUnencryptedPersistenceTest)
{
	ScopedQueueDir queueDir("unencrypted");

	FileInfo origFile(601);
	origFile.SetSubject("unencrypted.bin");
	origFile.SetFilename("unencrypted.bin");
	origFile.SetOrigname("unencrypted.bin");

	std::unique_ptr<ArticleInfo> art = std::make_unique<ArticleInfo>();
	art->SetPartNumber(1);
	art->SetSize(1000);
	art->SetMessageId("art1@unencrypted.com");
	art->SetSegmentIndex(std::nullopt);
	origFile.GetArticles()->push_back(std::move(art));

	BOOST_REQUIRE(g_DiskState->SaveFile(&origFile));

	FileInfo loadedFile(601);
	BOOST_REQUIRE(g_DiskState->LoadFile(&loadedFile, true, true));

	BOOST_REQUIRE_EQUAL(loadedFile.GetArticles()->size(), 1U);
	BOOST_CHECK(!loadedFile.GetArticles()->front()->HasSegmentIndex());
}

BOOST_AUTO_TEST_CASE(DiskStatePartialArticleLoadUnwindTest)
{
	ScopedQueueDir queueDir("unwind");

	// State file with 3 declared articles, where article 1 is valid, but article 2 is malformed
	const std::string corruptContent =
		"nzbget diskstate file version 8\n"
		"Unwind Subject\n"
		"unwind.bin\n"
		"unwind.bin\n"
		"unwind.bin\n"
		"1,12345678\n"
		"0,3000\n"
		"0,0\n"
		"0\n"
		"2,0\n"
		"1\n"
		"alt.binaries.test\n"
		"3\n"
		"1,1000,10\n"
		"art1@unwind.com\n"
		"2,corrupt_size,11\n"
		"art2@unwind.com\n"
		"3,1000,12\n"
		"art3@unwind.com\n";

	queueDir.WriteFile(701, corruptContent);

	FileInfo loaded(701);
	bool success = g_DiskState->LoadFile(&loaded, true, true);
	BOOST_CHECK(!success);
	// Articles vector must be completely cleared on error, not left partially populated
	BOOST_CHECK_EQUAL(loaded.GetArticles()->size(), 0U);
}

BOOST_AUTO_TEST_CASE(DiskStateCrlfLineEndingTest)
{
	ScopedQueueDir queueDir("crlf");

	// Valid version 8 state file using \r\n CRLF line endings
	const std::string crlfContent =
		"nzbget diskstate file version 8\r\n"
		"[1/3] - \"crlf.bin\" yEnc (1/2)\r\n"
		"crlf.bin\r\n"
		"crlf.bin\r\n"
		"crlf.bin\r\n"
		"1,12345678\r\n"
		"0,2000\r\n"
		"0,0\r\n"
		"0\r\n"
		"2,0\r\n"
		"1\r\n"
		"alt.binaries.test\r\n"
		"2\r\n"
		"1,1000,10\r\n"
		"art1@crlf.com\r\n"
		"2,1000,11\r\n"
		"art2@crlf.com\r\n";

	queueDir.WriteFile(801, crlfContent);

	FileInfo loaded(801);
	bool success = g_DiskState->LoadFile(&loaded, true, true);
	BOOST_CHECK(success);
	BOOST_REQUIRE_EQUAL(loaded.GetArticles()->size(), 2U);
	BOOST_CHECK_EQUAL(loaded.GetArticles()->at(0)->GetSegmentIndex().value(), 10U);
	BOOST_CHECK_EQUAL(loaded.GetArticles()->at(1)->GetSegmentIndex().value(), 11U);
}

BOOST_AUTO_TEST_SUITE_END()
