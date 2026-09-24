/*
 *  This file is part of nzbget. See <https://nzbget.com>.
 *
 *  Copyright (C) 2015-2016 Andrey Prygunkov <hugbug@users.sourceforge.net>
 *  Copyright (C) 2023-2026 Denis <denis@nzbget.com>
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
#include "NzbFile.h"
#include "DownloadInfo.h"
#include "FileSystem.h"

BOOST_AUTO_TEST_SUITE(QueueTest)

const fs::path CURR_DIR = fs::current_path();

void TestNzb(std::string testFilename, std::string expectedCategory)
{
	const fs::path nzbFilename = CURR_DIR / "nzbfile" / (testFilename + ".nzb");
	const fs::path infoFilename = CURR_DIR / "nzbfile" / (testFilename + ".txt");

	NzbFile nzbFile(nzbFilename.string().c_str(), "");
	BOOST_REQUIRE(nzbFile.Parse());

	BOOST_CHECK_EQUAL(expectedCategory, nzbFile.GetCategoryFromFile());

	FILE* infofile = fopen(infoFilename.string().c_str(), FOPEN_RB);
	BOOST_REQUIRE(infofile);
	char buffer[1024];

	while (fgets(buffer, sizeof(buffer), infofile) && *buffer == '#') ;
	BOOST_REQUIRE(*buffer);

	int fileCount = atoi(buffer);
	std::unique_ptr<NzbInfo> nzbInfo = nzbFile.DetachNzbInfo();
	BOOST_CHECK_EQUAL(nzbInfo->GetFileCount(), fileCount);
	char lastBuffer[1024];

	for (int i = 0; i < fileCount; i++)
	{
		while (fgets(buffer, sizeof(buffer), infofile) && *buffer == '#') ;
		BOOST_REQUIRE(*buffer);
		FileInfo* fileInfo = nzbInfo->GetFileList()->at(i).get();
		BOOST_REQUIRE(fileInfo);
		Util::TrimRight(buffer);
		BOOST_CHECK_EQUAL(std::string(fileInfo->GetFilename()), std::string(buffer));
		memcpy(lastBuffer, buffer, sizeof(buffer));
	}

	while (fgets(buffer, sizeof(buffer), infofile) && *buffer == '#') ;

	Util::TrimRight(buffer);

	if(strcmp(lastBuffer, buffer) == 0)
	{
		BOOST_CHECK(nzbFile.GetPassword().empty());
	}
	else
	{
		BOOST_CHECK_EQUAL(nzbFile.GetPassword(), std::string(buffer));
	}

	fclose(infofile);

	xmlCleanupParser();
}

BOOST_AUTO_TEST_CASE(NZBParserTest)
{
	TestNzb("dotless", "Movies");
	TestNzb("plain", "TV>4K");
	TestNzb("literal_gt", "TV > 4K");
	TestNzb("passwd{{thisisthepassword}}", "");
	TestNzb("passwdMeta", "");
	TestNzb("passwdEntity", "");
}

BOOST_AUTO_TEST_CASE(SanitizePathSegmentTest)
{
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("Clean.Release.Name"), "Clean.Release.Name");
	std::string testPath = FileSystem::SanitizePathSegment("../../etc/cron.d");
	BOOST_CHECK(testPath.find('/') == std::string::npos);
	BOOST_CHECK(testPath.find('\\') == std::string::npos);
	BOOST_CHECK(testPath.find("..") == std::string::npos);
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment(".."), "");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("."), "");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment(""), "");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("name:with*bad?chars"), "name_with_bad_chars");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("folder/sub\\name"), "folder_sub_name");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("trailing.dots...   "), "trailing.dots");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("   leading.space"), "leading.space");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("CON"), "_CON");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("NUL.txt"), "_NUL.txt");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("AUX"), "_AUX");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("COM1"), "_COM1");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("PRN.dat"), "_PRN.dat");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("LPT1"), "_LPT1");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("Vidéo.2026.mkv"), "Vidéo.2026.mkv");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("Mädchen.mp4"), "Mädchen.mp4");

	// Consecutive dots and spaces
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("..."), "");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment(".. "), "");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("prefix..middle...suffix"), "prefix_middle_suffix");
	std::string dotPath1 = FileSystem::SanitizePathSegment(".../");
	BOOST_CHECK(dotPath1.find('/') == std::string::npos);
	BOOST_CHECK(dotPath1.find("..") == std::string::npos);
	std::string dotPath2 = FileSystem::SanitizePathSegment("folder/...");
	BOOST_CHECK(dotPath2.find('/') == std::string::npos);
	BOOST_CHECK(dotPath2.find("..") == std::string::npos);

	// Long dot runs and length bounding
	std::string longDots(10000, '.');
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment(longDots), "");
	std::string longName(2000, 'a');
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment(longName).size(), 1024u);

	// UTF-8 boundary truncation: multi-byte character straddling byte 1024
	std::string splitUtf8 = std::string(1023, 'a') + "\xC3\xA9" + "tail";
	std::string cleanSplit = FileSystem::SanitizePathSegment(splitUtf8);
	BOOST_CHECK_EQUAL(cleanSplit.size(), 1023u);
	BOOST_CHECK_EQUAL(cleanSplit.back(), 'a');

	// UTF-8 multi-byte character entirely within 1024 limit is preserved
	std::string intactUtf8 = std::string(1022, 'a') + "\xC3\xA9" + "tail";
	std::string cleanIntact = FileSystem::SanitizePathSegment(intactUtf8);
	BOOST_CHECK_EQUAL(cleanIntact.size(), 1024u);
	BOOST_CHECK_EQUAL(cleanIntact.substr(1022), "\xC3\xA9");

	// Drive and UNC paths
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("C:\\Windows"), "C__Windows");
	BOOST_CHECK_EQUAL(FileSystem::SanitizePathSegment("\\\\server\\share"), "__server_share");
}

BOOST_AUTO_TEST_CASE(SanitizeRelativePathTest)
{
	std::string sep(1, PATH_SEPARATOR);
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("Movies"), "Movies");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("TV/HD"), "TV" + sep + "HD");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("TV / HD"), "TV" + sep + "HD");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("TV>HD"), "TV_HD");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("TV > HD"), "TV _ HD");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("TV\\Shows"), "TV" + sep + "Shows");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("TV/../../HD"), "TV" + sep + "HD");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("TV/./HD"), "TV" + sep + "HD");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("TV/.."), "TV");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("TV/../../../../../etc"), "TV" + sep + "etc");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("../../Movies/4K"), "Movies" + sep + "4K");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("/var/www/"), "var" + sep + "www");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("C:\\Movies\\SciFi"), "C_" + sep + "Movies" + sep + "SciFi");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("Séries/HD"), "Séries" + sep + "HD");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath(".."), "");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("../.."), "");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath(""), "");

	// Consecutive dots in relative paths
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("myfolder/.../file"), "myfolder" + sep + "file");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("myfolder/.. /file"), "myfolder" + sep + "file");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath(".../file"), "file");

	// Absolute and UNC path normalization
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("\\\\remote-server\\share\\data"), "remote-server" + sep + "share" + sep + "data");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("//remote-server/share/data"), "remote-server" + sep + "share" + sep + "data");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("C:\\Windows\\System32"), "C_" + sep + "Windows" + sep + "System32");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("C:/Windows/System32"), "C_" + sep + "Windows" + sep + "System32");

	// Reserved device names in path components
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("LPT1/subfolder"), "_LPT1" + sep + "subfolder");
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath("movies/CON/item"), "movies" + sep + "_CON" + sep + "item");
}

namespace
{
	void WriteTempNzb(const fs::path& filePath, std::string_view headMeta)
	{
		std::ofstream out(filePath.string());
		out << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		    << "<!DOCTYPE nzb PUBLIC \"-//newzBin//DTD NZB 1.0//EN\" \"http://www.newzbin.com/DTD/nzb/nzb-1.0.dtd\">\n"
		    << "<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n"
		    << "<head>\n"
		    << headMeta << "\n"
		    << "</head>\n"
		    << "<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"&quot;testfile.mkv&quot; yEnc (1/1)\">\n"
		    << "<groups><group>alt.binaries.test</group></groups>\n"
		    << "<segments><segment bytes=\"100\" number=\"1\">test@msgid</segment></segments>\n"
		    << "</file>\n"
		    << "</nzb>\n";
	}

	void WriteRawNzb(const fs::path& filePath, std::string_view content)
	{
		std::ofstream out(filePath.string());
		out << content;
	}
}

BOOST_AUTO_TEST_CASE(NzbFileMetaParsingTest)
{
	const fs::path tempNzb = fs::temp_directory_path() / "nzbget_test_meta_name.nzb";
	WriteTempNzb(tempNzb,
		"<meta type=\"name\">My.Clean.Release.Name.S01E01 &amp; Special.Edition</meta>\n"
		"<meta type=\"title\">My.Clean.Release.Name.S01E01.mkv</meta>\n"
		"<meta type=\"category\">TV / HD</meta>\n"
		"<meta type=\"password\">secret123</meta>");

	NzbFile nzbFile(tempNzb.string().c_str(), "");
	BOOST_REQUIRE(nzbFile.Parse());

	BOOST_CHECK_EQUAL(nzbFile.GetMetaName(), "My.Clean.Release.Name.S01E01 & Special.Edition");
	BOOST_CHECK_EQUAL(nzbFile.GetMetaTitle(), "My.Clean.Release.Name.S01E01.mkv");
	BOOST_CHECK_EQUAL(nzbFile.GetPassword(), "secret123");
	BOOST_CHECK_EQUAL(nzbFile.GetCategoryFromFile(), "TV / HD");

	auto nzbInfo = nzbFile.DetachNzbInfo();
	BOOST_REQUIRE(nzbInfo);
	BOOST_CHECK_EQUAL(nzbInfo->GetMetaName(), "My.Clean.Release.Name.S01E01 & Special.Edition");

	fs::remove(tempNzb);
}

BOOST_AUTO_TEST_CASE(NzbFileMetaTitleFallbackTest)
{
	const fs::path tempNzb = fs::temp_directory_path() / "nzbget_test_meta_title_fallback.nzb";
	WriteTempNzb(tempNzb, "<meta type=\"title\">Fallback.Release.Title.mkv</meta>");

	NzbFile nzbFile(tempNzb.string().c_str(), "");
	BOOST_REQUIRE(nzbFile.Parse());

	BOOST_CHECK_EQUAL(nzbFile.GetMetaName(), "Fallback.Release.Title.mkv");
	BOOST_CHECK_EQUAL(nzbFile.GetMetaTitle(), "Fallback.Release.Title.mkv");

	auto nzbInfo = nzbFile.DetachNzbInfo();
	BOOST_REQUIRE(nzbInfo);
	BOOST_CHECK_EQUAL(nzbInfo->GetMetaName(), "Fallback.Release.Title.mkv");

	fs::remove(tempNzb);
}

BOOST_AUTO_TEST_CASE(NzbFileMetaPathValidationTest)
{
	const fs::path tempNzb = fs::temp_directory_path() / "nzbget_test_meta_validation.nzb";
	WriteTempNzb(tempNzb,
		"<meta type=\"name\">../../../../test/folder/release</meta>\n"
		"<meta type=\"category\">../../../../media/downloads</meta>");

	NzbFile nzbFile(tempNzb.string().c_str(), "");
	BOOST_REQUIRE(nzbFile.Parse());

	// Slashes and .. in meta name must be normalized and cannot escape base directories
	BOOST_CHECK(nzbFile.GetMetaName().find('/') == std::string::npos);
	BOOST_CHECK(nzbFile.GetMetaName().find('\\') == std::string::npos);
	BOOST_CHECK(nzbFile.GetMetaName().find("..") == std::string::npos);

	// Relative path separators and .. must be safely normalized when generating category path
	std::string sep(1, PATH_SEPARATOR);
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath(nzbFile.GetCategoryFromFile()), "media" + sep + "downloads");

	fs::remove(tempNzb);
}

BOOST_AUTO_TEST_CASE(NzbFileCategoryControlCharsTest)
{
	const fs::path tempNzb = fs::temp_directory_path() / "nzbget_test_meta_control_chars.nzb";
	WriteTempNzb(tempNzb,
		"<meta type=\"category\">\r\n\t  Movies\r\n/\t4K  \r\n</meta>");

	NzbFile nzbFile(tempNzb.string().c_str(), "");
	BOOST_REQUIRE(nzbFile.Parse());

	// Control characters must be stripped to protect line-based DiskState persistence
	const std::string& category = nzbFile.GetCategoryFromFile();
	BOOST_CHECK(category.find('\n') == std::string::npos);
	BOOST_CHECK(category.find('\r') == std::string::npos);
	BOOST_CHECK(category.find('\t') == std::string::npos);

	std::string sep(1, PATH_SEPARATOR);
	BOOST_CHECK_EQUAL(FileSystem::SanitizeRelativePath(category), "Movies" + sep + "4K");

	fs::remove(tempNzb);
}

BOOST_AUTO_TEST_CASE(EmptyNzbNameFallbackTest)
{
	// MakeNiceNzbName must never return empty string
	BOOST_CHECK_EQUAL(NzbInfo::MakeNiceNzbName("   .nzb", true), "nzb");
	BOOST_CHECK_EQUAL(NzbInfo::MakeNiceNzbName(".nzb", true), "nzb");
	BOOST_CHECK_EQUAL(NzbInfo::MakeNiceNzbName("...", true), "nzb");
	BOOST_CHECK_EQUAL(NzbInfo::MakeNiceNzbName("   ", true), "nzb");
	BOOST_CHECK_EQUAL(NzbInfo::MakeNiceNzbName("", true), "nzb");
	BOOST_CHECK_EQUAL(NzbInfo::MakeNiceNzbName("   .nzb", false), ".nzb");

	// Valid names must not be altered
	BOOST_CHECK_EQUAL(NzbInfo::MakeNiceNzbName("My.Release.nzb", true), "My.Release");
	BOOST_CHECK_EQUAL(NzbInfo::MakeNiceNzbName("My.Release.nzb", false), "My.Release.nzb");
	BOOST_CHECK_EQUAL(NzbInfo::MakeNiceNzbName("My.Release", false), "My.Release");

	// Consecutive dots normalized
	BOOST_CHECK_EQUAL(NzbInfo::MakeNiceNzbName("My..Release...nzb", true), "My_Release");
}

BOOST_AUTO_TEST_CASE(BuildFinalDirNameUniqueIdTest)
{
	NzbInfo nzbInfo1;
	nzbInfo1.SetName("");
	std::string finalDir1 = *nzbInfo1.BuildFinalDirName();
	std::string expectedSuffix1 = "nzb-" + std::to_string(nzbInfo1.GetId());
	BOOST_CHECK(finalDir1.rfind(expectedSuffix1) != std::string::npos);

	NzbInfo nzbInfo2;
	nzbInfo2.SetName("");
	std::string finalDir2 = *nzbInfo2.BuildFinalDirName();
	std::string expectedSuffix2 = "nzb-" + std::to_string(nzbInfo2.GetId());
	BOOST_CHECK(finalDir2.rfind(expectedSuffix2) != std::string::npos);

	// Both empty downloads must have different final directories
	BOOST_CHECK_NE(finalDir1, finalDir2);
}

BOOST_AUTO_TEST_CASE(NzbFileSegmentIdentityTest)
{
	const fs::path tempNzb = fs::temp_directory_path() / "nzbget_test_segment_identity_reversed.nzb";
	const std::string xml =
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<!DOCTYPE nzb PUBLIC \"-//newzBin//DTD NZB 1.0//EN\" \"http://www.newzbin.com/DTD/nzb/nzb-1.0.dtd\">\n"
		"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[2/2] - &quot;file2.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg2_1@test</segment></segments>\n"
		"</file>\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[1/2] - &quot;file1.bin&quot; yEnc (1/2)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments>\n"
		"<segment bytes=\"100\" number=\"1\">msg1_1@test</segment>\n"
		"<segment bytes=\"100\" number=\"2\">msg1_2@test</segment>\n"
		"</segments>\n"
		"</file>\n"
		"</nzb>\n";

	WriteRawNzb(tempNzb, xml);

	auto verifyParsed = [](const fs::path& path)
	{
		NzbFile nzbFile(path.string().c_str(), "");
		BOOST_REQUIRE(nzbFile.Parse());

		auto nzbInfo = nzbFile.DetachNzbInfo();
		BOOST_REQUIRE(nzbInfo);
		FileList* fileList = nzbInfo->GetFileList();
		BOOST_REQUIRE_EQUAL(fileList->size(), 2U);

		FileInfo* file1 = nullptr;
		FileInfo* file2 = nullptr;
		for (FileInfo* fi : fileList)
		{
			if (fi->HasFileOrdinal() && fi->GetFileOrdinal().value() == 1U)
			{
				file1 = fi;
			}
			else if (fi->HasFileOrdinal() && fi->GetFileOrdinal().value() == 2U)
			{
				file2 = fi;
			}
		}

		BOOST_REQUIRE(file1 != nullptr);
		BOOST_REQUIRE(file2 != nullptr);

		BOOST_CHECK_EQUAL(file1->GetTotalFiles().value(), 2U);
		BOOST_CHECK_EQUAL(file1->GetSegmentIndexBase().value(), 1U);
		BOOST_REQUIRE_EQUAL(file1->GetArticles()->size(), 2U);
		BOOST_REQUIRE(file1->GetArticles()->at(0)->HasSegmentIndex());
		BOOST_CHECK_EQUAL(file1->GetArticles()->at(0)->GetSegmentIndex().value(), 1U);
		BOOST_REQUIRE(file1->GetArticles()->at(1)->HasSegmentIndex());
		BOOST_CHECK_EQUAL(file1->GetArticles()->at(1)->GetSegmentIndex().value(), 2U);

		BOOST_CHECK_EQUAL(file2->GetTotalFiles().value(), 2U);
		BOOST_CHECK_EQUAL(file2->GetSegmentIndexBase().value(), 3U);
		BOOST_REQUIRE_EQUAL(file2->GetArticles()->size(), 1U);
		BOOST_REQUIRE(file2->GetArticles()->at(0)->HasSegmentIndex());
		BOOST_CHECK_EQUAL(file2->GetArticles()->at(0)->GetSegmentIndex().value(), 3U);
	};

	// 1. Reversed XML order produces canonical continuous assignment
	verifyParsed(tempNzb);

	// 2. Repeated parse produces identical values
	verifyParsed(tempNzb);

	fs::remove(tempNzb);
}

BOOST_AUTO_TEST_CASE(NzbFileSegmentIdentityMalformedAndOrdinaryTest)
{
	auto parseAndCheckAllUnset = [](std::string_view xml, const std::string& filename)
	{
		const fs::path tempNzb = fs::temp_directory_path() / filename;
		WriteRawNzb(tempNzb, xml);

		NzbFile nzbFile(tempNzb.string().c_str(), "");
		BOOST_REQUIRE(nzbFile.Parse());

		auto nzbInfo = nzbFile.DetachNzbInfo();
		BOOST_REQUIRE(nzbInfo);
		FileList* fileList = nzbInfo->GetFileList();
		BOOST_REQUIRE(!fileList->empty());

		for (FileInfo* fi : fileList)
		{
			BOOST_CHECK(!fi->HasFileOrdinal());
			BOOST_CHECK(!fi->HasTotalFiles());
			BOOST_CHECK(!fi->HasSegmentIndexBase());
			for (auto& art : *fi->GetArticles())
			{
				if (art)
				{
					BOOST_CHECK(!art->HasSegmentIndex());
				}
			}
		}

		fs::remove(tempNzb);
	};

	// 1. Ordinary unnumbered NZB
	parseAndCheckAllUnset(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"&quot;ordinary.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg@test</segment></segments>\n"
		"</file>\n"
		"</nzb>\n",
		"nzbget_test_ordinary.nzb"
	);

	// 2. Bracketed text that is not a counter
	parseAndCheckAllUnset(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[GROUP] - &quot;file.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg@test</segment></segments>\n"
		"</file>\n"
		"</nzb>\n",
		"nzbget_test_bracket_non_counter.nzb"
	);

	// 3. Zero file ordinal [0/2]
	parseAndCheckAllUnset(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[0/2] - &quot;file1.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg1@test</segment></segments>\n"
		"</file>\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[2/2] - &quot;file2.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg2@test</segment></segments>\n"
		"</file>\n"
		"</nzb>\n",
		"nzbget_test_zero_ordinal.nzb"
	);

	// 4. Overflow uint32 in counter [4294967296/2]
	parseAndCheckAllUnset(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[4294967296/2] - &quot;file1.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg1@test</segment></segments>\n"
		"</file>\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[2/2] - &quot;file2.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg2@test</segment></segments>\n"
		"</file>\n"
		"</nzb>\n",
		"nzbget_test_overflow_ordinal.nzb"
	);

	// 5. Inconsistent declared totals: [1/3] and [2/2]
	parseAndCheckAllUnset(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[1/3] - &quot;file1.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg1@test</segment></segments>\n"
		"</file>\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[2/2] - &quot;file2.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg2@test</segment></segments>\n"
		"</file>\n"
		"</nzb>\n",
		"nzbget_test_inconsistent_total.nzb"
	);

	// 6. Incomplete ordinal set (missing file 2: [1/3] and [3/3])
	parseAndCheckAllUnset(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[1/3] - &quot;file1.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg1@test</segment></segments>\n"
		"</file>\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[3/3] - &quot;file3.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg3@test</segment></segments>\n"
		"</file>\n"
		"</nzb>\n",
		"nzbget_test_incomplete_ordinal.nzb"
	);

	// 7. Duplicate file ordinals: [1/2] and [1/2]
	parseAndCheckAllUnset(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[1/2] - &quot;file1.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg1@test</segment></segments>\n"
		"</file>\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[1/2] - &quot;file2.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments><segment bytes=\"100\" number=\"1\">msg2@test</segment></segments>\n"
		"</file>\n"
		"</nzb>\n",
		"nzbget_test_duplicate_ordinal.nzb"
	);

	// 8. Declared part gap: parts 1 and 3 present, part 2 missing
	// Part 3 MUST NOT be compacted into position 2. Declared part must remain 3.
	{
		const fs::path tempNzb = fs::temp_directory_path() / "nzbget_test_part_gap.nzb";
		const std::string xml =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n"
			"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[1/1] - &quot;file1.bin&quot; yEnc (1/3)\">\n"
			"<groups><group>alt.binaries.test</group></groups>\n"
			"<segments>\n"
			"<segment bytes=\"100\" number=\"1\">msg1_1@test</segment>\n"
			"<segment bytes=\"100\" number=\"3\">msg1_3@test</segment>\n"
			"</segments>\n"
			"</file>\n"
			"</nzb>\n";
		WriteRawNzb(tempNzb, xml);

		NzbFile nzbFile(tempNzb.string().c_str(), "");
		BOOST_REQUIRE(nzbFile.Parse());

		auto nzbInfo = nzbFile.DetachNzbInfo();
		BOOST_REQUIRE(nzbInfo);
		FileList* fileList = nzbInfo->GetFileList();
		BOOST_REQUIRE_EQUAL(fileList->size(), 1U);

		FileInfo* fi = fileList->front().get();
		BOOST_CHECK(!fi->HasFileOrdinal());
		BOOST_CHECK(!fi->HasTotalFiles());
		BOOST_CHECK(!fi->HasSegmentIndexBase());
		BOOST_CHECK_EQUAL(fi->GetMissedArticles(), 1);

		ArticleList* articles = fi->GetArticles();
		BOOST_REQUIRE_EQUAL(articles->size(), 2U);
		BOOST_CHECK_EQUAL((*articles)[0]->GetPartNumber(), 1);
		BOOST_CHECK(!(*articles)[0]->HasSegmentIndex());
		// Part 3 retains declared part 3, never compacted to 2
		BOOST_CHECK_EQUAL((*articles)[1]->GetPartNumber(), 3);
		BOOST_CHECK(!(*articles)[1]->HasSegmentIndex());

		fs::remove(tempNzb);
	}

	// 9. Duplicate declared parts: segment number 1 declared twice in one file
	parseAndCheckAllUnset(
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
		"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n"
		"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[1/1] - &quot;file1.bin&quot; yEnc (1/1)\">\n"
		"<groups><group>alt.binaries.test</group></groups>\n"
		"<segments>\n"
		"<segment bytes=\"100\" number=\"1\">msg1_1@test</segment>\n"
		"<segment bytes=\"100\" number=\"1\">msg1_1_dupe@test</segment>\n"
		"</segments>\n"
		"</file>\n"
		"</nzb>\n",
		"nzbget_test_duplicate_part.nzb"
	);

	// 10. Scheduling/queue order change does not alter already attached fields
	{
		const fs::path tempNzb = fs::temp_directory_path() / "nzbget_test_queue_reorder.nzb";
		const std::string xml =
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n"
			"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[1/2] - &quot;file1.bin&quot; yEnc (1/2)\">\n"
			"<groups><group>alt.binaries.test</group></groups>\n"
			"<segments>\n"
			"<segment bytes=\"100\" number=\"1\">msg1_1@test</segment>\n"
			"<segment bytes=\"100\" number=\"2\">msg1_2@test</segment>\n"
			"</segments>\n"
			"</file>\n"
			"<file poster=\"poster@test.com\" date=\"1335508618\" subject=\"[2/2] - &quot;file2.bin&quot; yEnc (1/1)\">\n"
			"<groups><group>alt.binaries.test</group></groups>\n"
			"<segments>\n"
			"<segment bytes=\"100\" number=\"1\">msg2_1@test</segment>\n"
			"</segments>\n"
			"</file>\n"
			"</nzb>\n";
		WriteRawNzb(tempNzb, xml);

		NzbFile nzbFile(tempNzb.string().c_str(), "");
		BOOST_REQUIRE(nzbFile.Parse());

		auto nzbInfo = nzbFile.DetachNzbInfo();
		BOOST_REQUIRE(nzbInfo);
		FileList* fileList = nzbInfo->GetFileList();
		BOOST_REQUIRE_EQUAL(fileList->size(), 2U);

		FileInfo* f1 = fileList->at(0).get();
		FileInfo* f2 = fileList->at(1).get();

		// Record values before simulated reorder
		BOOST_CHECK_EQUAL(f1->GetFileOrdinal().value(), 1U);
		BOOST_CHECK_EQUAL(f1->GetSegmentIndexBase().value(), 1U);
		BOOST_CHECK_EQUAL(f1->GetArticles()->at(0)->GetSegmentIndex().value(), 1U);
		BOOST_CHECK_EQUAL(f1->GetArticles()->at(1)->GetSegmentIndex().value(), 2U);

		BOOST_CHECK_EQUAL(f2->GetFileOrdinal().value(), 2U);
		BOOST_CHECK_EQUAL(f2->GetSegmentIndexBase().value(), 3U);
		BOOST_CHECK_EQUAL(f2->GetArticles()->at(0)->GetSegmentIndex().value(), 3U);

		// Perturb operational order (simulate queue priority or file reordering)
		std::vector<FileInfo*> reorderedQueue{ f2, f1 };
		BOOST_CHECK_EQUAL(reorderedQueue[0]->GetFileOrdinal().value(), 2U);
		BOOST_CHECK_EQUAL(reorderedQueue[0]->GetSegmentIndexBase().value(), 3U);
		BOOST_CHECK_EQUAL(reorderedQueue[0]->GetArticles()->at(0)->GetSegmentIndex().value(), 3U);

		BOOST_CHECK_EQUAL(reorderedQueue[1]->GetFileOrdinal().value(), 1U);
		BOOST_CHECK_EQUAL(reorderedQueue[1]->GetSegmentIndexBase().value(), 1U);
		BOOST_CHECK_EQUAL(reorderedQueue[1]->GetArticles()->at(0)->GetSegmentIndex().value(), 1U);
		BOOST_CHECK_EQUAL(reorderedQueue[1]->GetArticles()->at(1)->GetSegmentIndex().value(), 2U);

		fs::remove(tempNzb);
	}
}

BOOST_AUTO_TEST_SUITE_END()
