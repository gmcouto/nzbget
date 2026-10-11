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
#include "Log.h"

#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(NNTPTest)

BOOST_AUTO_TEST_CASE(CorruptedLine1BootstrapFailClosedTest)
{
	YEncDecryptor decryptor("test123");
	Decoder decoder;
	decoder.SetDecryptor(&decryptor);

	// Corrupted line 1 that does not begin with =ybegin and cannot be decrypted as FF1 control line
	std::string corruptedArticle =
		"4b376d5839704c32715238764e34775a99999999CORRUPT_LINE_ONE_DATA\r\n"
		"=ypart line=1 size=10\r\n"
		"data\r\n"
		"=yend size=4\r\n.\r\n";

	decoder.DecodeBuffer(corruptedArticle.data(), static_cast<int>(corruptedArticle.size()));
	Decoder::EStatus checkStatus = decoder.Check();
	BOOST_CHECK_EQUAL(static_cast<int>(checkStatus), static_cast<int>(Decoder::dsAuthFailed));
	BOOST_CHECK(decoder.GetDecryptedData().empty());
}

BOOST_AUTO_TEST_SUITE_END()
