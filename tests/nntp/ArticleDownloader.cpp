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
#include "Options.h"
#include "ServerPool.h"
#include "StatMeter.h"
#include "WorkState.h"
#include "YEncDecryptor.h"
#include "ArticleWriter.h"
#include "YEncTestHelpers.h"

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <memory>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <cstddef>

// ArticleWriter.h (already included) declares ArticleCache and the
// g_ArticleCache global. The cache-backed scenario below installs a real
// ArticleCache so the commit path exercises the segment-cache sink.

namespace stdfs = std::filesystem;

#include <sodium.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

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

#ifndef WIN32

// Real local NNTP server driving ArticleDownloader::Run() over loopback
// sockets. Proves: corrupt-primary/valid-backup provider failover over real
// NNTP, DirectWrite on/off, allocated article cache, and that a failed
// provider's bytes never reach the article cache or final file (zero-output
// at every sink). Replaces the former decoder-only failover assertion.
namespace
{

class LocalNntpServer
{
public:
	LocalNntpServer(std::string responseArticle, std::atomic<int>* requestCounter) :
		m_responseArticle(std::move(responseArticle)),
		m_requestCounter(requestCounter)
	{
		m_listenFd = socket(AF_INET, SOCK_STREAM, 0);
		int opt = 1;
		setsockopt(m_listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
		sockaddr_in addr = {};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = 0;
		if (bind(m_listenFd, (sockaddr*)&addr, sizeof(addr)) != 0 || listen(m_listenFd, 5) != 0)
		{
			// Test infrastructure failure: cannot start local NNTP server
			m_port = -1;
			m_thread = std::thread([this]() { Run(); });
			return;
		}
		socklen_t len = sizeof(addr);
		getsockname(m_listenFd, (sockaddr*)&addr, &len);
		m_port = ntohs(addr.sin_port);
		m_thread = std::thread([this]() { Run(); });
	}

	~LocalNntpServer()
	{
		m_stop = true;
		if (m_listenFd >= 0)
		{
			close(m_listenFd);
		}
		if (m_thread.joinable())
		{
			m_thread.join();
		}
	}

	int GetPort() const { return m_port; }

private:
	int m_listenFd = -1;
	int m_port = 0;
	std::string m_responseArticle;
	std::atomic<int>* m_requestCounter;
	std::atomic<bool> m_stop{false};
	std::thread m_thread;

	void Run()
	{
		while (!m_stop)
		{
			fd_set fds;
			FD_ZERO(&fds);
			FD_SET(m_listenFd, &fds);
			timeval tv = {0, 50000};
			if (select(m_listenFd + 1, &fds, nullptr, nullptr, &tv) <= 0)
			{
				continue;
			}
			int clientFd = accept(m_listenFd, nullptr, nullptr);
			if (clientFd < 0)
			{
				continue;
			}
			const char welcome[] = "200 Welcome test NNTP\r\n";
			send(clientFd, welcome, sizeof(welcome) - 1, 0);
			char buf[4096];
			std::string lineBuf;
			while (!m_stop)
			{
				int r = recv(clientFd, buf, sizeof(buf), 0);
				if (r <= 0) break;
				lineBuf.append(buf, r);
				size_t nl;
				while ((nl = lineBuf.find('\n')) != std::string::npos)
				{
					std::string cmd = lineBuf.substr(0, nl);
					lineBuf.erase(0, nl + 1);
					while (!cmd.empty() && (cmd.back() == '\r' || cmd.back() == ' '))
					{
						cmd.pop_back();
					}
					if (cmd.rfind("GROUP", 0) == 0)
					{
						const char resp[] = "211 0 0 0 test.group\r\n";
						send(clientFd, resp, sizeof(resp) - 1, 0);
					}
					else if (cmd.rfind("BODY", 0) == 0 || cmd.rfind("ARTICLE", 0) == 0)
					{
						(*m_requestCounter)++;
						std::string resp = "222 1 " + cmd.substr(cmd.find(' ') + 1) + "\r\n";
						resp += m_responseArticle;
						send(clientFd, resp.data(), resp.size(), 0);
					}
					else if (cmd == "QUIT")
					{
						const char resp[] = "205 Bye\r\n";
						send(clientFd, resp, sizeof(resp) - 1, 0);
						break;
					}
					else
					{
						const char resp[] = "500 Command unrecognized\r\n";
						send(clientFd, resp, sizeof(resp) - 1, 0);
					}
				}
			}
			close(clientFd);
		}
	}
};

struct DownloaderEnv
{
	Options::CmdOptList cmdOpts;
	std::unique_ptr<Options> options;
	Options* oldOptions = nullptr;
	std::unique_ptr<StatMeter> statMeter;
	StatMeter* oldStatMeter = nullptr;
	std::unique_ptr<ArticleCache> articleCache;
	// Captured at construction; the destructor restores it so the framework
	// teardown never sees the test-local pool (which dies with the test).
	ServerPool* oldServerPool = nullptr;
	ArticleCache* oldArticleCache = nullptr;

	explicit DownloaderEnv(const std::string& tempDir, bool directWrite = false, int articleCache = 0,
		bool rawArticle = false)
	{
		oldServerPool = g_ServerPool;
		oldOptions = g_Options;
		oldArticleCache = g_ArticleCache;
		std::string tempDirOpt = "TempDir=" + tempDir;
		// cmdOpts stores raw const char* pointers: every string backing them
		// must outlive the Options constructor (a cacheOpt scoped inside this
		// if-block made Options read freed memory → the cache-backed leg
		// silently ran with ArticleCache=0).
		std::string cacheOpt;
		std::string rawArticleOpt;
		cmdOpts.push_back(tempDirOpt.c_str());
		if (directWrite)
		{
			cmdOpts.push_back("DirectWrite=yes");
		}
		if (articleCache > 0)
		{
			cacheOpt = "ArticleCache=" + std::to_string(articleCache);
			cmdOpts.push_back(cacheOpt.c_str());
		}
		if (rawArticle)
		{
			rawArticleOpt = "RawArticle=yes";
			cmdOpts.push_back(rawArticleOpt.c_str());
		}
		options = std::make_unique<Options>(&cmdOpts, nullptr);
		g_Options = options.get();
		oldStatMeter = g_StatMeter;
		statMeter = std::make_unique<StatMeter>();
		g_StatMeter = statMeter.get();
		// WorkState defaults to TempPauseDownload=true; the downloader would
		// break with adRetry before touching the network.
		g_WorkState->SetTempPauseDownload(false);
		// The production binary owns the ArticleCache in nzbget.cpp; the test
		// binary has no global cache, so a cache-backed scenario must install
		// one — otherwise the writer silently falls back to disk staging and
		// the "segment lands in ArticleCache" leg would be a tautology.
		if (articleCache > 0)
		{
			this->articleCache = std::make_unique<ArticleCache>();
			g_ArticleCache = this->articleCache.get();
		}
		// StatMeter::Init sizes the per-server volume table from g_ServerPool;
		// the test must set g_ServerPool BEFORE constructing this env.
		statMeter->Init();
	}

	~DownloaderEnv()
	{
		// Options::~Options() nulls g_Options unconditionally, so the test
		// Options instance must be destroyed BEFORE restoring the global —
		// otherwise the restored pointer is nulled right after restoration.
		options.reset();
		statMeter.reset();
		articleCache.reset();
		g_ArticleCache = oldArticleCache;
		g_Options = oldOptions;
		g_StatMeter = oldStatMeter;
		// g_ServerPool is restored to the framework's global pool; the test
		// pool is a test-local stack object and must never outlive the test.
		g_ServerPool = oldServerPool;
		g_WorkState->SetTempPauseDownload(true);
	}
};

// Shared test helpers : one hex/yEnc helper set for all NNTP test TUs.
using namespace YEncTest;

// Builds a valid combined-mode encrypted wire article for a single-part segment.
// password/salt/segmentIndex/nonce/key all come from YEncDecryptor's normal
// derivation so the resulting article decrypts with the same inputs.
std::string BuildValidEncryptedWireArticle(const std::string& password,
	const std::vector<uint8_t>& salt, uint32_t segmentIndex,
	const std::string& filename, const std::vector<uint8_t>& plaintext)
{
	YEncDecryptor encDec(password);
	BOOST_REQUIRE(encDec.EnsureMasterKey(salt.data()));

	uint8_t nonce[24];
	BOOST_REQUIRE(encDec.DeriveBodyNonce(segmentIndex, nonce));

	std::vector<uint8_t> aad = YEncDecryptor::BuildAad(filename, 1, 1, plaintext.size());
	std::vector<uint8_t> sealed(plaintext.size() + 16);
	unsigned long long sealedLen = 0;
	BOOST_REQUIRE(crypto_aead_xchacha20poly1305_ietf_encrypt(
		sealed.data(), &sealedLen, plaintext.data(), plaintext.size(),
		aad.data(), aad.size(), nullptr, nonce,
		encDec.GetCachedMasterKey().data()) == 0);
	sealed.resize(sealedLen);

	std::vector<uint8_t> ct(sealed.begin(), sealed.end() - 16);
	std::vector<uint8_t> tag(sealed.end() - 16, sealed.end());

	std::string line1Plain = "=ybegin line=128 size=" + std::to_string(plaintext.size()) + " name=" + filename;
	std::vector<uint8_t> wire1;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line1Plain.data()), line1Plain.size(),
		segmentIndex, 1, true, salt.data(), wire1
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	char tagHex[33] = {0};
	for (size_t i = 0; i < 16; ++i)
	{
		snprintf(tagHex + 2 * i, 3, "%02x", tag[i]);
	}
	std::string line2Plain = "=yencryption cipher=XChaCha20-Poly1305 salt=" + YEncTest::BinToHex(salt.data(), 16) +
		" index=" + YEncTest::FormatHex8(segmentIndex) + " tag=" + tagHex;
	std::vector<uint8_t> wire2;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line2Plain.data()), line2Plain.size(),
		segmentIndex, 2, false, salt.data(), wire2
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	// yEnc-encode the ciphertext (with full '='-escape handling)
	std::string encLine;
	for (uint8_t c : ct)
	{
		uint8_t e = (uint8_t)((c + 42) % 256);
		if (e == 0x00 || e == 0x0A || e == 0x0D || e == 0x3D)
		{
			encLine += '=';
			e = (uint8_t)((e + 64) % 256);
		}
		encLine += (char)e;
	}

	Crc32 crc;
	crc.Append(ct.data(), static_cast<uint32>(ct.size()));
	std::string line4Plain = "=yend size=" + std::to_string(plaintext.size()) +
		" crc32=" + YEncTest::FormatHex8(crc.Finish());
	std::vector<uint8_t> wire4;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line4Plain.data()), line4Plain.size(),
		segmentIndex, 4, false, salt.data(), wire4
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string fullWire;
	fullWire.append(reinterpret_cast<const char*>(wire1.data()), wire1.size()); fullWire += "\r\n";
	fullWire.append(reinterpret_cast<const char*>(wire2.data()), wire2.size()); fullWire += "\r\n";
	fullWire += encLine; fullWire += "\r\n";
	fullWire.append(reinterpret_cast<const char*>(wire4.data()), wire4.size()); fullWire += "\r\n.\r\n";
	return fullWire;
}

// Full corrupt-primary → valid-backup scenario over real loopback NNTP.
// directWrite / articleCache parameterize the writer path under test.
void RunEncryptedFailoverScenario(const char* filename, bool directWrite, int articleCache)
{
	stdfs::path tempDir = stdfs::temp_directory_path() / "nzbget_failover_nntp_test";
	stdfs::create_directories(tempDir);
	stdfs::path tempDirOpt = stdfs::temp_directory_path() / "nzbget_failover_nntp_temp";
	stdfs::create_directories(tempDirOpt);

	const std::string password = "test123";
	const std::vector<uint8_t> salt = YEncTest::HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
	const std::vector<uint8_t> plaintext = YEncTest::HexToBin("48656c6c6f20576f726c642e747874ff");
	const uint32_t segmentIndex = 1;

	std::string validWire = BuildValidEncryptedWireArticle(password, salt, segmentIndex, filename, plaintext);
	std::string corruptWire = validWire;
	// Flip one byte in the yEnc-encoded body so the AEAD tag no longer matches.
	size_t bodyStart = corruptWire.find("\r\n", corruptWire.find("\r\n") + 2) + 2;
	corruptWire[bodyStart] = (char)(corruptWire[bodyStart] == 'A' ? 'B' : 'A');

	std::atomic<int> primaryRequests{0};
	std::atomic<int> backupRequests{0};
	LocalNntpServer primary(corruptWire, &primaryRequests);
	LocalNntpServer backup(validWire, &backupRequests);

	// Two servers: primary at level 0 (fails), backup at level 1 (succeeds)
	ServerPool pool;
	auto server1 = std::make_unique<NewsServer>(1, true, "primary", "127.0.0.1", primary.GetPort(), 0,
		"", "", false, false, nullptr, 1, 0, 0, 0, false, Options::cvStrict);
	auto server2 = std::make_unique<NewsServer>(2, true, "backup", "127.0.0.1", backup.GetPort(), 0,
		"", "", false, false, nullptr, 1, 0, 1, 0, false, Options::cvStrict);
	pool.AddServer(std::move(server1));
	pool.AddServer(std::move(server2));
	pool.InitConnections();
	pool.SetRetryInterval(60);

	DownloaderEnv env(tempDirOpt.string(), directWrite, articleCache);
	g_ServerPool = &pool;
	// StatMeter::Init sizes the per-server volume table from g_ServerPool; the
	// test pool must be installed first.
	env.statMeter->Init();

	NzbInfo nzbInfo;
	nzbInfo.SetDestDir(tempDir.string().c_str());
	nzbInfo.SetYEncEncrypted(true);
	nzbInfo.GetParameters()->SetParameter("*Unpack:Password", password.c_str());

	FileInfo fileInfo;
	fileInfo.SetNzbInfo(&nzbInfo);
	fileInfo.SetFilename(filename);
	fileInfo.SetTime(Util::CurrentTime());

	fileInfo.GetArticles()->resize(1);
	(*fileInfo.GetArticles())[0] = std::make_unique<ArticleInfo>();
	(*fileInfo.GetArticles())[0]->SetMessageId("<failover-msg@test>");
	(*fileInfo.GetArticles())[0]->SetSize(static_cast<int>(plaintext.size()));
	(*fileInfo.GetArticles())[0]->SetPartNumber(1);

	ArticleDownloader downloader;
	downloader.SetFileInfo(&fileInfo);
	downloader.SetArticleInfo((*fileInfo.GetArticles())[0].get());
	downloader.SetInfoName("failover_article");
	downloader.SetConnection(pool.GetConnection(0, nullptr, nullptr));

	downloader.Run();

	// Both providers must have been contacted (failover happened over real NNTP)
	BOOST_CHECK_GE(primaryRequests.load(), 1);
	BOOST_CHECK_GE(backupRequests.load(), 1);

	// The downloader must succeed (valid article fetched from backup provider)
	BOOST_CHECK_EQUAL(static_cast<int>(downloader.GetStatus()), static_cast<int>(ArticleDownloader::adFinished));

	// The article CRC is the CRC of the authenticated plaintext (not the
	// ciphertext), so PAR2 quick verification can use it.
	Crc32 plaintextCrc;
	plaintextCrc.Append(const_cast<uint8_t*>(plaintext.data()), static_cast<uint32>(plaintext.size()));
	BOOST_CHECK_EQUAL((*fileInfo.GetArticles())[0]->GetCrc(), plaintextCrc.Finish());

	// The committed segment must be the authenticated plaintext (from backup),
	// never the corrupted primary's bytes. With ArticleCache=0 the plaintext is
	// written to the per-article result file; with a cache allocation it lands
	// in the segment cache. DirectWrite must be bypassed for encrypted releases.
	const char* content = (*fileInfo.GetArticles())[0]->GetSegmentContent();
	if (articleCache > 0)
	{
		// The cache-backed leg must genuinely use the segment-cache sink: the
		// env installs a real ArticleCache, so Alloc() must have succeeded.
		BOOST_REQUIRE(content != nullptr);
		BOOST_CHECK_EQUAL(memcmp(content, plaintext.data(), plaintext.size()), 0);
	}
	else if (content != nullptr)
	{
		BOOST_CHECK_EQUAL(memcmp(content, plaintext.data(), plaintext.size()), 0);
	}
	else
	{
		const char* resultFilename = (*fileInfo.GetArticles())[0]->GetResultFilename();
		BOOST_REQUIRE(resultFilename != nullptr);
		std::ifstream resultFile(resultFilename, std::ios::binary);
		BOOST_REQUIRE(resultFile);
		std::vector<char> fileBytes((std::istreambuf_iterator<char>(resultFile)),
			std::istreambuf_iterator<char>());
		BOOST_REQUIRE_EQUAL(fileBytes.size(), plaintext.size());
		BOOST_CHECK_EQUAL(memcmp(fileBytes.data(), plaintext.data(), plaintext.size()), 0);
	}

	// DirectWrite gating: with DirectWrite=on and an encrypted release, the
	// final destination file must never have been created by the writer.
	if (directWrite)
	{
		BOOST_CHECK(!stdfs::exists(tempDir / filename));
	}

	stdfs::remove_all(tempDir);
	stdfs::remove_all(tempDirOpt);
}

} // anonymous namespace

BOOST_AUTO_TEST_CASE(EncryptedProviderFailoverOverRealNntpTest)
{
	// Real local NNTP: corrupt primary → valid backup failover. The primary
	// provider serves an article with a corrupted body (auth failure); the
	// backup serves the valid article. ArticleDownloader::Run() must finish
	// with adFinished and the committed plaintext must come only from the
	// backup provider.
	//
	// Runs the full Run() loop three times, covering the integration matrix:
	//   1. DirectWrite=off,  ArticleCache=0 (disk staging via result file)
	//   2. DirectWrite=on,   ArticleCache=0 (direct-write must be bypassed for
	//      encrypted releases; staged to result file instead)
	//   3. DirectWrite=off,  ArticleCache=250 (segment lands in the article cache)
	RunEncryptedFailoverScenario("failover_disk.dat", false, 0);
	RunEncryptedFailoverScenario("failover_directwrite.dat", true, 0);
	RunEncryptedFailoverScenario("failover_cached.dat", false, 250);
}

BOOST_AUTO_TEST_CASE(EncryptedRawArticleRejectedBeforeRequestTest)
{
	// RawArticle + encrypted job must be rejected BEFORE the
	// BODY/ARTICLE request — no bytes fetched, nothing committed, raw status
	// adFatalError (Run() breaks immediately and normalizes to failure).
	stdfs::path tempDir = stdfs::temp_directory_path() / "nzbget_rawart_test";
	stdfs::path tempDirOpt = stdfs::temp_directory_path() / "nzbget_rawart_temp";
	stdfs::create_directories(tempDir);
	stdfs::create_directories(tempDirOpt);

	const std::string password = "test123";
	const std::vector<uint8_t> salt = YEncTest::HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
	const std::vector<uint8_t> plaintext = YEncTest::HexToBin("48656c6c6f20576f726c642e747874ff");
	const std::string filename = "rawarticle.dat";

	std::string validWire = BuildValidEncryptedWireArticle(password, salt, 1, filename, plaintext);

	std::atomic<int> requests{0};
	LocalNntpServer server(validWire, &requests);

	ServerPool pool;
	auto server1 = std::make_unique<NewsServer>(1, true, "primary", "127.0.0.1", server.GetPort(), 0,
		"", "", false, false, nullptr, 1, 0, 0, 0, false, Options::cvStrict);
	pool.AddServer(std::move(server1));
	pool.InitConnections();
	pool.SetRetryInterval(60);

	DownloaderEnv env(tempDirOpt.string(), false, 0, /*rawArticle=*/true);
	g_ServerPool = &pool;
	env.statMeter->Init();

	NzbInfo nzbInfo;
	nzbInfo.SetDestDir(tempDir.string().c_str());
	nzbInfo.SetYEncEncrypted(true);
	nzbInfo.GetParameters()->SetParameter("*Unpack:Password", password.c_str());

	FileInfo fileInfo;
	fileInfo.SetNzbInfo(&nzbInfo);
	fileInfo.SetFilename(filename);
	fileInfo.SetTime(Util::CurrentTime());

	fileInfo.GetArticles()->resize(1);
	(*fileInfo.GetArticles())[0] = std::make_unique<ArticleInfo>();
	(*fileInfo.GetArticles())[0]->SetMessageId("<rawarticle-msg@test>");
	(*fileInfo.GetArticles())[0]->SetSize(static_cast<int>(plaintext.size()));
	(*fileInfo.GetArticles())[0]->SetPartNumber(1);

	ArticleDownloader downloader;
	downloader.SetFileInfo(&fileInfo);
	downloader.SetArticleInfo((*fileInfo.GetArticles())[0].get());
	downloader.SetInfoName("rawarticle_article");
	downloader.SetConnection(pool.GetConnection(0, nullptr, nullptr));

	BOOST_REQUIRE(g_Options->GetRawArticle());

	// Drive Download() directly: Run() normalizes adFatalError to adFailed,
	// but the reviewer-required assertion is the raw pre-normalization status.
	ArticleDownloader::EStatus status = downloader.TestDownload();

	BOOST_CHECK_EQUAL(static_cast<int>(status), static_cast<int>(ArticleDownloader::adFatalError));

	// The rejection must precede the article request: no BODY/ARTICLE was sent.
	BOOST_CHECK_EQUAL(requests.load(), 0);

	// Nothing committed: no segment content, no result file, no destination file.
	BOOST_CHECK((*fileInfo.GetArticles())[0]->GetSegmentContent() == nullptr);
	BOOST_CHECK((*fileInfo.GetArticles())[0]->GetResultFilename() == nullptr ||
		!stdfs::exists((*fileInfo.GetArticles())[0]->GetResultFilename()));
	BOOST_CHECK(!stdfs::exists(tempDir / filename));

	g_ServerPool = env.oldServerPool;
	stdfs::remove_all(tempDir);
	stdfs::remove_all(tempDirOpt);
}

BOOST_AUTO_TEST_CASE(EncryptedAllProvidersExhaustedTest)
{
	// Exhaustion leg: BOTH providers serve the corrupted article. The
	// downloader must exhaust all levels/servers and end in failure
	// (adFailed/adNotFound after Run() normalization), with ZERO bytes
	// committed to any sink — cache, result file, or final destination.
	stdfs::path tempDir = stdfs::temp_directory_path() / "nzbget_exhaust_test";
	stdfs::path tempDirOpt = stdfs::temp_directory_path() / "nzbget_exhaust_temp";
	stdfs::create_directories(tempDir);
	stdfs::create_directories(tempDirOpt);

	const std::string password = "test123";
	const std::vector<uint8_t> salt = YEncTest::HexToBin("1a2b3c4d5e6f7890abcdef1234567890");
	const std::vector<uint8_t> plaintext = YEncTest::HexToBin("48656c6c6f20576f726c642e747874ff");
	const std::string filename = "exhaust.dat";

	std::string validWire = BuildValidEncryptedWireArticle(password, salt, 1, filename, plaintext);
	std::string corruptWire = validWire;
	size_t bodyStart = corruptWire.find("\r\n", corruptWire.find("\r\n") + 2) + 2;
	corruptWire[bodyStart] = (char)(corruptWire[bodyStart] == 'A' ? 'B' : 'A');

	std::atomic<int> primaryRequests{0};
	std::atomic<int> backupRequests{0};
	LocalNntpServer primary(corruptWire, &primaryRequests);
	LocalNntpServer backup(corruptWire, &backupRequests);

	ServerPool pool;
	auto server1 = std::make_unique<NewsServer>(1, true, "primary", "127.0.0.1", primary.GetPort(), 0,
		"", "", false, false, nullptr, 1, 0, 0, 0, false, Options::cvStrict);
	auto server2 = std::make_unique<NewsServer>(2, true, "backup", "127.0.0.1", backup.GetPort(), 0,
		"", "", false, false, nullptr, 1, 0, 1, 0, false, Options::cvStrict);
	pool.AddServer(std::move(server1));
	pool.AddServer(std::move(server2));
	pool.InitConnections();
	pool.SetRetryInterval(60);

	DownloaderEnv env(tempDirOpt.string(), false, 0);
	g_ServerPool = &pool;
	env.statMeter->Init();

	NzbInfo nzbInfo;
	nzbInfo.SetDestDir(tempDir.string().c_str());
	nzbInfo.SetYEncEncrypted(true);
	nzbInfo.GetParameters()->SetParameter("*Unpack:Password", password.c_str());

	FileInfo fileInfo;
	fileInfo.SetNzbInfo(&nzbInfo);
	fileInfo.SetFilename(filename);
	fileInfo.SetTime(Util::CurrentTime());

	fileInfo.GetArticles()->resize(1);
	(*fileInfo.GetArticles())[0] = std::make_unique<ArticleInfo>();
	(*fileInfo.GetArticles())[0]->SetMessageId("<exhaust-msg@test>");
	(*fileInfo.GetArticles())[0]->SetSize(static_cast<int>(plaintext.size()));
	(*fileInfo.GetArticles())[0]->SetPartNumber(1);

	ArticleDownloader downloader;
	downloader.SetFileInfo(&fileInfo);
	downloader.SetArticleInfo((*fileInfo.GetArticles())[0].get());
	downloader.SetInfoName("exhaust_article");
	downloader.SetConnection(pool.GetConnection(0, nullptr, nullptr));

	downloader.Run();

	// Both providers were contacted (each served the corrupted article) and
	// the loop exhausted all levels: final status is failure.
	BOOST_CHECK_GE(primaryRequests.load(), 1);
	BOOST_CHECK_GE(backupRequests.load(), 1);
	int finalStatus = static_cast<int>(downloader.GetStatus());
	BOOST_CHECK(finalStatus == static_cast<int>(ArticleDownloader::adFailed) ||
		finalStatus == static_cast<int>(ArticleDownloader::adNotFound));

	// Zero bytes committed to ANY sink:
	// - no segment in the article cache
	BOOST_CHECK((*fileInfo.GetArticles())[0]->GetSegmentContent() == nullptr);
	BOOST_CHECK_EQUAL((*fileInfo.GetArticles())[0]->GetSegmentSize(), 0);
	// - no result file / temp file on disk
	BOOST_CHECK(!stdfs::exists(tempDirOpt / "1.001"));
	BOOST_CHECK(!stdfs::exists(tempDirOpt / "1.001.tmp"));
	// - no final destination file
	BOOST_CHECK(!stdfs::exists(tempDir / filename));

	g_ServerPool = env.oldServerPool;
	stdfs::remove_all(tempDir);
	stdfs::remove_all(tempDirOpt);
}

#endif // !WIN32

BOOST_AUTO_TEST_SUITE_END()
