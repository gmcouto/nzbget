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
	fileInfo.SetFileOrdinal(2);
	fileInfo.SetTotalFiles(5);
	fileInfo.SetSegmentIndexBase(10);

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

	BOOST_CHECK(loaded.HasFileOrdinal());
	if (loaded.HasFileOrdinal())
	{
		BOOST_CHECK_EQUAL(loaded.GetFileOrdinal().value(), 2U);
	}

	BOOST_CHECK(loaded.HasTotalFiles());
	if (loaded.HasTotalFiles())
	{
		BOOST_CHECK_EQUAL(loaded.GetTotalFiles().value(), 5U);
	}

	BOOST_CHECK(loaded.HasSegmentIndexBase());
	if (loaded.HasSegmentIndexBase())
	{
		BOOST_CHECK_EQUAL(loaded.GetSegmentIndexBase().value(), 10U);
	}

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
	origFile.SetFileOrdinal(3);
	origFile.SetTotalFiles(7);
	origFile.SetSegmentIndexBase(25);

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

	BOOST_CHECK_EQUAL(load1.GetFileOrdinal().value(), 3U);
	BOOST_CHECK_EQUAL(load1.GetTotalFiles().value(), 7U);
	BOOST_CHECK_EQUAL(load1.GetSegmentIndexBase().value(), 25U);
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

	BOOST_CHECK_EQUAL(load2.GetFileOrdinal().value(), 3U);
	BOOST_CHECK_EQUAL(load2.GetTotalFiles().value(), 7U);
	BOOST_CHECK_EQUAL(load2.GetSegmentIndexBase().value(), 25U);
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
	BOOST_CHECK_EQUAL(loadSummaryOnly.GetFileOrdinal().value(), 3U);
	BOOST_CHECK_EQUAL(loadSummaryOnly.GetTotalFiles().value(), 7U);
	BOOST_CHECK_EQUAL(loadSummaryOnly.GetSegmentIndexBase().value(), 25U);

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

	// Hand-authored version-7 diskstate file fixture (no identity line, no segmentIndex)
	const std::string v7Content =
		"nzbget diskstate file version 7\n"
		"[1/2] - \"legacy.bin\" yEnc (1/2)\n"
		"legacy.bin\n"
		"legacy.bin\n"
		"legacy.bin\n"
		"1,12345678\n"
		"0,2500\n"
		"0,0\n"
		"0\n"
		"2,0\n"
		"1\n"
		"alt.binaries.test\n"
		"2\n"
		"1,1000\n"
		"art1@legacy.com\n"
		"2,1500\n"
		"art2@legacy.com\n";

	queueDir.WriteFile(201, v7Content);

	FileInfo loadedV7(201);
	BOOST_REQUIRE(g_DiskState->LoadFile(&loadedV7, true, true));

	BOOST_CHECK_EQUAL(std::string(loadedV7.GetFilename()), "legacy.bin");
	BOOST_CHECK_EQUAL(std::string(loadedV7.GetSubject()), "[1/2] - \"legacy.bin\" yEnc (1/2)");
	BOOST_CHECK_EQUAL(loadedV7.GetSize(), 2500);

	// In version 7, identity fields MUST remain unset
	BOOST_CHECK(!loadedV7.HasFileOrdinal());
	BOOST_CHECK(!loadedV7.HasTotalFiles());
	BOOST_CHECK(!loadedV7.HasSegmentIndexBase());

	BOOST_REQUIRE_EQUAL(loadedV7.GetArticles()->size(), 2U);

	ArticleInfo* art1 = loadedV7.GetArticles()->at(0).get();
	BOOST_CHECK_EQUAL(art1->GetPartNumber(), 1);
	BOOST_CHECK_EQUAL(art1->GetSize(), 1000);
	BOOST_CHECK_EQUAL(std::string(art1->GetMessageId()), "art1@legacy.com");
	BOOST_CHECK(!art1->HasSegmentIndex());

	ArticleInfo* art2 = loadedV7.GetArticles()->at(1).get();
	BOOST_CHECK_EQUAL(art2->GetPartNumber(), 2);
	BOOST_CHECK_EQUAL(art2->GetSize(), 1500);
	BOOST_CHECK_EQUAL(std::string(art2->GetMessageId()), "art2@legacy.com");
	BOOST_CHECK(!art2->HasSegmentIndex());
}

BOOST_AUTO_TEST_CASE(DiskStateVersion8OrdinaryUnencryptedRoundtripTest)
{
	ScopedQueueDir queueDir("v8ordinary");

	// An ordinary unencrypted file in version 8 has identity unset
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

	// Verify the file content on disk has the 0,0,0 line and article 0 segmentIndex
	fs::path savedPath = queueDir.m_tempPath / "301";
	std::ifstream ifs(savedPath);
	std::string line;
	int lineNum = 0;
	bool foundIdentityLine = false;
	bool foundArticle1 = false;
	while (std::getline(ifs, line))
	{
		lineNum++;
		if (lineNum == 6)
		{
			// Line 6 should be the file identity line: 0,0,0
			BOOST_CHECK_EQUAL(line, "0,0,0");
			foundIdentityLine = true;
		}
		if (line == "1,800,0")
		{
			foundArticle1 = true;
		}
	}
	BOOST_CHECK(foundIdentityLine);
	BOOST_CHECK(foundArticle1);

	// Load and verify fields are unset
	FileInfo loaded(301);
	BOOST_REQUIRE(g_DiskState->LoadFile(&loaded, true, true));

	BOOST_CHECK(!loaded.HasFileOrdinal());
	BOOST_CHECK(!loaded.HasTotalFiles());
	BOOST_CHECK(!loaded.HasSegmentIndexBase());
	BOOST_REQUIRE_EQUAL(loaded.GetArticles()->size(), 2U);
	BOOST_CHECK(!loaded.GetArticles()->at(0)->HasSegmentIndex());
	BOOST_CHECK(!loaded.GetArticles()->at(1)->HasSegmentIndex());
	BOOST_CHECK_EQUAL(loaded.GetArticles()->at(0)->GetPartNumber(), 1);
	BOOST_CHECK_EQUAL(loaded.GetArticles()->at(1)->GetPartNumber(), 2);
}

BOOST_AUTO_TEST_CASE(DiskStateMalformedAndCorruptTest)
{
	ScopedQueueDir queueDir("corrupt");

	auto createTemplate = [](const std::string& identityLine, const std::string& art1Line, const std::string& art2Line)
	{
		return std::string("nzbget diskstate file version 8\n") +
			"Test Subject\n" +
			"corrupt.bin\n" +
			"corrupt.bin\n" +
			"corrupt.bin\n" +
			identityLine + "\n" +
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

	// 1. Incomplete tuple (missing base)
	checkFails(createTemplate("2,5", "1,1000,10", "2,1000,11"));

	// 2. Extra tuple field
	checkFails(createTemplate("2,5,10,99", "1,1000,10", "2,1000,11"));

	// 3. Non-digit character in identity line
	checkFails(createTemplate("2,five,10", "1,1000,10", "2,1000,11"));
	checkFails(createTemplate("2,5,10abc", "1,1000,10", "2,1000,11"));

	// 4. Negative integer representation
	checkFails(createTemplate("-2,5,10", "1,1000,10", "2,1000,11"));
	checkFails(createTemplate("2,-5,10", "1,1000,10", "2,1000,11"));

	// 5. Ordinal out of range (fileOrdinal > totalFiles: 6 > 5)
	checkFails(createTemplate("6,5,10", "1,1000,10", "2,1000,11"));

	// 6. Zero fileOrdinal when totalFiles > 0
	checkFails(createTemplate("0,5,10", "1,1000,10", "2,1000,11"));

	// 7. Zero totalFiles when fileOrdinal > 0
	checkFails(createTemplate("1,0,10", "1,1000,10", "2,1000,11"));

	// 7b. Zero segmentIndexBase when fileOrdinal > 0
	checkFails(createTemplate("1,1,0", "1,1000,10", "2,1000,11"));

	// 8. Overflow beyond uint32 max
	checkFails(createTemplate("4294967296,5,10", "1,1000,10", "2,1000,11"));
	checkFails(createTemplate("1,4294967296,10", "1,1000,10", "2,1000,11"));
	checkFails(createTemplate("1,5,4294967296", "1,1000,10", "2,1000,11"));

	// 9. Article missing segmentIndex in version 8 (only part,size)
	checkFails(createTemplate("2,5,10", "1,1000", "2,1000,11"));

	// 10. Article with negative segmentIndex
	checkFails(createTemplate("2,5,10", "1,1000,-1", "2,1000,11"));

	// 11. Article with segmentIndex 0 when file has identity
	checkFails(createTemplate("2,5,10", "1,1000,0", "2,1000,11"));

	// 12. Article with segmentIndex > 0 when file has NO identity (0,0,0)
	checkFails(createTemplate("0,0,0", "1,1000,10", "2,1000,0"));

	// 13. Article with declared part number 0
	checkFails(createTemplate("2,5,10", "0,1000,10", "2,1000,11"));

	// 14. Truncated file before articles section completes
	std::string truncated =
		"nzbget diskstate file version 8\n"
		"Test Subject\n"
		"corrupt.bin\n"
		"corrupt.bin\n"
		"corrupt.bin\n"
		"2,5,10\n";
	checkFails(truncated);

	// 15. Invalid format version 0
	std::string v0Content =
		"nzbget diskstate file version 0\n"
		"Test Subject\n"
		"corrupt.bin\n";
	checkFails(v0Content);

	// 16. Missing or invalid signature
	std::string badSig =
		"bad signature file version 8\n"
		"Test Subject\n";
	checkFails(badSig);
}

BOOST_AUTO_TEST_SUITE_END()
