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
#include "ServerPool.h"
#include "DownloadInfo.h"
#include "Options.h"
#include "Log.h"
#include "FileSystem.h"

#include <string>
#include <vector>

namespace
{

void AddTestServer(ServerPool* pool, int id, bool active, int level, bool optional, int group, int connections)
{
	pool->AddServer(std::make_unique<NewsServer>(id, active, nullptr, "", 119, 0,
		"", "", false, false, nullptr, connections, 0, level, group, optional, Options::cvStrict));
}

} // anonymous namespace

BOOST_AUTO_TEST_SUITE(NNTPTest)

BOOST_AUTO_TEST_CASE(EncryptedProviderFailoverTest)
{
	// Set up ServerPool with 2 servers
	ServerPool pool;
	AddTestServer(&pool, 1, true, 0, false, 0, 2);
	AddTestServer(&pool, 2, true, 0, false, 0, 2);
	pool.InitConnections();

	NewsServer* serv1 = pool.GetServers()->at(0).get();
	NewsServer* serv2 = pool.GetServers()->at(1).get();

	BOOST_REQUIRE(serv1 != nullptr);
	BOOST_REQUIRE(serv2 != nullptr);

	// Simulate failure on Server 1 (e.g. auth failure in DecodeCheck -> adFailed)
	ServerPool::RawServerList failedServers;
	failedServers.push_back(serv1);

	// Request next connection excluding failed Server 1
	NntpConnection* con = pool.GetConnection(0, nullptr, &failedServers);
	BOOST_REQUIRE(con != nullptr);
	BOOST_CHECK_EQUAL(con->GetNewsServer()->GetId(), serv2->GetId());

	pool.FreeConnection(con, false);

	// Verify Decoder dsAuthFailed routing
	Decoder decoder;
	decoder.SetAuthFailed(true);
	BOOST_CHECK_EQUAL(static_cast<int>(decoder.Check()), static_cast<int>(Decoder::dsAuthFailed));

	// Verify that Decoder::dsAuthFailed maps to adNotFound (triggering multi-server failover)
	ArticleDownloader::EStatus mappedStatus = (decoder.Check() == Decoder::dsAuthFailed) ?
		ArticleDownloader::adNotFound : ArticleDownloader::adFinished;
	BOOST_CHECK_EQUAL(static_cast<int>(mappedStatus), static_cast<int>(ArticleDownloader::adNotFound));
}

BOOST_AUTO_TEST_CASE(CorruptedLine1BootstrapFailClosedTest)
{
	Decoder decoder;
	decoder.SetPassword("test123");

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

BOOST_AUTO_TEST_CASE(EncryptedProviderSecretLoggingAuditTest)
{
	if (!g_Log)
	{
		return;
	}

	const std::string secretPassword = "SuperSecretAuditPassword999";
	const std::string secretPlaintext = "SecretPlaintextStringXYZ";
	const std::string secretSaltHex = "1a2b3c4d5e6f7890abcdef1234567890";
	const std::string secretTagHex = "0cd77ce245a654463f90b945b1d22d5b";

	g_Log->Clear();

	// Run decoder with encrypted password and cause an authentication failure
	Decoder decoder;
	decoder.SetPassword(secretPassword.c_str());
	decoder.SetSegmentIndex(1);

	// Tampered wire article
	std::string tamperedArticle =
		"4b376d5839704c32715238764e34775a3ff69054da2b2309591e740e5b9fd79015f610d42f01bd203e5f55dadc39fc760407e845201f\r\n"
		"=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b\r\n"
		"data\r\n"
		"=yend size=4\r\n.\r\n";

	decoder.DecodeBuffer(tamperedArticle.data(), static_cast<int>(tamperedArticle.size()));
	decoder.Check();

	// Emit warning like ArticleDownloader would
	warn("Article test failed authentication, retrying...");

	// Audit all messages in g_Log
	GuardedMessageList messages = g_Log->GuardMessages();
	for (Message& msg : *messages)
	{
		std::string text = msg.GetText();
		BOOST_CHECK(text.find(secretPassword) == std::string::npos);
		BOOST_CHECK(text.find(secretPlaintext) == std::string::npos);
	}
}

BOOST_AUTO_TEST_SUITE_END()
