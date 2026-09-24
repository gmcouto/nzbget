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

BOOST_AUTO_TEST_SUITE_END()
