/*
 *  This file is part of nzbget. See <https://nzbget.com>.
 *
 *  Copyright (C) 2025-2026 Denis <denis@nzbget.com>
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
#include "Decoder.h"
#include "YEncoder.h"
#include "YEncDecryptor.h"
#include <sodium.h>
#include <iomanip>
#include <sstream>

BOOST_AUTO_TEST_SUITE(NNTPTest)

std::string yEncEncode(const std::string& data)
{
	std::string encodedData = "";
	for (unsigned char c : data)
	{
		encodedData += static_cast<unsigned char>((c + 42) % 256);
	}
	return encodedData;
}

/**
 * Single message:
 * 
 * =ybegin line=128 size=111401 name=al_larsonbw030_ball.jpg\r\n
 * )_)=J*:tpsp*++++V+V**)_*m*0./0/.00/011024:44334>896:A>....\r\n
 * ...Â´RÌ´RÌ´RÌ´RÌ´RÌ´RÌ´RÌ´RÌ´RÌ´RÌ´RÌ´RÌ´RÍ©)_\r\n
 * =yend size=111401\r\n
 * .\r\n
*/
BOOST_AUTO_TEST_CASE(SingleMessageTest)
{
	Decoder decoder;
	decoder.SetCrcCheck(true);
	std::stringstream ss;

	const std::string data = "nzbget";
	const std::string crc = "a30bff0d";
	const std::string filename = "name.dat";
	const std::string encodedData = yEncEncode(data);

	ss << "=ybegin line=128 size=" << data.size() << " name=" << filename << "\r\n";
	ss << encodedData << "\r\n";
	ss << "=yend size=" << data.size() << " crc32=" << crc << "\r\n";
	ss << ".\r\n";

	std::string msg = ss.str();

	int len = decoder.DecodeBuffer(msg.data(), msg.size());

	auto status = decoder.Check();
	auto size = decoder.GetSize();
	auto calculatedCrc = decoder.GetCalculatedCrc();
	auto articleName = decoder.GetArticleFilename();
	auto format = decoder.GetFormat();
	auto eof = decoder.GetEof();
	auto res = msg.substr(0, len);

	BOOST_CHECK_EQUAL(status, Decoder::dsFinished);
	BOOST_CHECK_EQUAL(articleName, filename);
	BOOST_CHECK_EQUAL(size, 6);
	BOOST_CHECK_EQUAL(calculatedCrc, 0xa30bff0d);
	BOOST_CHECK_EQUAL(format, Decoder::efYenc);
	BOOST_CHECK_EQUAL(eof, true);
	BOOST_CHECK_EQUAL(res, "nzbget");
}

/**
 * Multipart message:
 * 
 * =ybegin part=1 total=10 line=128 size=500000 name=mybinary.dat\r\n
 * =ypart begin=1 end=100000\r\n
 * .... data\r\n
 * =yend size=100000 part=1 pcrc32=abcdef12\r\n
 * .\r\n
 * =ybegin part=5 line=128 size=500000 name=mybinary.dat\r\n
 * =ypart begin=400001 end=500000\r\n
 * .... data\r\n
 * =yend size=100000 part=10 pcrc32=12a45c78 crc32=abcdef12\r\n
 * .\r\n
*/
BOOST_AUTO_TEST_CASE(MultipartMessageTest)
{
	Decoder decoder;
	decoder.SetCrcCheck(true);
	std::stringstream ss;

	const std::string crc = "a30bff0d";
	const std::string data = "nzb";
	const std::string encodedData = yEncEncode(data);
	const std::string pcrc = "cb64ae30";
	const std::string filename = "name.dat";

	const std::string data2 = "get";
	const std::string encodedData2 = yEncEncode(data2);
	const std::string pcrc2 = "fd3b2e70";
	const size_t totalSize = data.size() + data2.size();

	ss << "=ybegin part=1 total=2 line=128 size=" << totalSize << " name=" << filename << "\r\n";
	ss << "=ypart begin=1 end=" << data.size() << "\r\n";
	ss << encodedData << "\r\n";
	ss << "=yend size=" << data.size() << " pcrc32=" << pcrc << "\r\n";
	ss << ".\r\n";

	std::string msg = ss.str();
	ss.str("");

	ss << "=ybegin part=2 total=2 line=128 size=" << totalSize << " name=" << filename << "\r\n";
	ss << "=ypart begin=" << data.size() + 1 << " end=" << totalSize << "\r\n";
	ss << encodedData2 << "\r\n";
	ss << "=yend size=" << data2.size() << " pcrc32=" << pcrc2 << " crc32=" << crc << "\r\n";
	ss << ".\r\n";

	std::string msg2 = ss.str();

	int len = decoder.DecodeBuffer(msg.data(), msg.size());
	{
		auto status = decoder.Check();
		auto size = decoder.GetSize();
		auto calculatedCrc = decoder.GetCalculatedCrc();
		auto articleName = decoder.GetArticleFilename();
		auto format = decoder.GetFormat();
		auto eof = decoder.GetEof();
		auto res = msg.substr(0, len);

		BOOST_CHECK_EQUAL(status, Decoder::dsFinished);
		BOOST_CHECK_EQUAL(articleName, filename);
		BOOST_CHECK_EQUAL(size, totalSize);
		BOOST_CHECK_EQUAL(calculatedCrc, 0xcb64ae30);
		BOOST_CHECK_EQUAL(format, Decoder::efYenc);
		BOOST_CHECK_EQUAL(eof, true);
		BOOST_CHECK_EQUAL(res, "nzb");
	}

	decoder.Clear();
	decoder.SetCrcCheck(true);

	int len2 = decoder.DecodeBuffer(msg2.data(), msg2.size());

	auto articleName = decoder.GetArticleFilename();
	auto status = decoder.Check();
	auto size = decoder.GetSize();
	auto calculatedCrc = decoder.GetCalculatedCrc();
	auto eof = decoder.GetEof();
	auto res = msg2.substr(0, len);

	BOOST_CHECK_EQUAL(articleName, filename);
	BOOST_CHECK_EQUAL(status, Decoder::dsFinished);
	BOOST_CHECK_EQUAL(len, data2.size());
	BOOST_CHECK_EQUAL(len + len2, totalSize);
	BOOST_CHECK_EQUAL(size, totalSize);
	BOOST_CHECK_EQUAL(calculatedCrc, 0xfd3b2e70);
	BOOST_CHECK_EQUAL(eof, true);
	BOOST_CHECK_EQUAL(res, "get");
}

/**
 * Unusual multipart message where there's no \r\n separating between name=... and =ypart:
 * 
 * =ybegin part=1 total=10 line=128 size=500000 name=mybinary.dat=ypart begin=1 end=100000\r\n
 * .... data\r\n
 * =yend size=100000 part=1 pcrc32=abcdef12\r\n
 * .\r\n
 * =ybegin part=5 line=128 size=500000 name=mybinary.dat\r\n
 * =ypart begin=400001 end=500000\r\n
 * .... data\r\n
 * =yend size=100000 part=10 pcrc32=12a45c78 crc32=abcdef12\r\n
 * .\r\n
*/
BOOST_AUTO_TEST_CASE(UnusualMultipartMessageTest)
{
	Decoder decoder;
	decoder.SetCrcCheck(true);
	std::stringstream ss;

	const std::string crc = "a30bff0d";
	const std::string data = "nzb";
	const std::string encodedData = yEncEncode(data);
	const std::string pcrc = "cb64ae30";
	const std::string filename = "name.dat";

	const std::string data2 = "get";
	const std::string encodedData2 = yEncEncode(data2);
	const std::string pcrc2 = "fd3b2e70";
	const size_t totalSize = data.size() + data2.size();

	ss << "=ybegin part=1 total=2 line=128 size=" << totalSize << " name=" << filename;
	ss << "=ypart begin=1 end=" << data.size() << "\r\n";
	ss << encodedData << "\r\n";
	ss << "=yend size=" << data.size() << " pcrc32=" << pcrc << "\r\n";
	ss << ".\r\n";

	std::string msg = ss.str();
	ss.str("");

	ss << "=ybegin part=2 total=2 line=128 size=" << totalSize << " name=" << filename;
	ss << "=ypart begin=" << data.size() + 1 << " end=" << totalSize << "\r\n";
	ss << encodedData2 << "\r\n";
	ss << "=yend size=" << data2.size() << " pcrc32=" << pcrc2 << " crc32=" << crc << "\r\n";
	ss << ".\r\n";

	std::string msg2 = ss.str();

	int len = decoder.DecodeBuffer(msg.data(), msg.size());
	{
		auto status = decoder.Check();
		auto size = decoder.GetSize();
		auto calculatedCrc = decoder.GetCalculatedCrc();
		auto articleName = decoder.GetArticleFilename();
		auto format = decoder.GetFormat();
		auto eof = decoder.GetEof();
		auto res = msg.substr(0, len);

		BOOST_CHECK_EQUAL(status, Decoder::dsFinished);
		BOOST_CHECK_EQUAL(articleName, filename);
		BOOST_CHECK_EQUAL(size, totalSize);
		BOOST_CHECK_EQUAL(calculatedCrc, 0xcb64ae30);
		BOOST_CHECK_EQUAL(format, Decoder::efYenc);
		BOOST_CHECK_EQUAL(eof, true);
		BOOST_CHECK_EQUAL(res, "nzb");
	}

	decoder.Clear();
	decoder.SetCrcCheck(true);

	int len2 = decoder.DecodeBuffer(msg2.data(), msg2.size());

	auto articleName = decoder.GetArticleFilename();
	auto status = decoder.Check();
	auto size = decoder.GetSize();
	auto calculatedCrc = decoder.GetCalculatedCrc();
	auto eof = decoder.GetEof();
	auto res = msg2.substr(0, len);

	BOOST_CHECK_EQUAL(articleName, filename);
	BOOST_CHECK_EQUAL(status, Decoder::dsFinished);
	BOOST_CHECK_EQUAL(len, data2.size());
	BOOST_CHECK_EQUAL(len + len2, totalSize);
	BOOST_CHECK_EQUAL(size, totalSize);
	BOOST_CHECK_EQUAL(calculatedCrc, 0xfd3b2e70);
	BOOST_CHECK_EQUAL(eof, true);
	BOOST_CHECK_EQUAL(res, "get");
}

BOOST_AUTO_TEST_CASE(BufferOverflowTest)
{
	Decoder decoder;
	decoder.SetRawMode(true);

	constexpr int bufSize = 4096;
	auto buf = std::make_unique<char[]>(bufSize);
	memset(buf.get(), 'x', bufSize);

	int len = decoder.DecodeBuffer(buf.get(), bufSize);
	BOOST_CHECK_EQUAL(len, bufSize);
	BOOST_CHECK_EQUAL(decoder.GetEof(), false);
}

static std::vector<uint8_t> HexToBytesHelper(const std::string& hex)
{
	std::vector<uint8_t> bytes;
	for (size_t i = 0; i < hex.length(); i += 2)
	{
		unsigned int byteVal = 0;
		sscanf(hex.c_str() + i, "%02x", &byteVal);
		bytes.push_back(static_cast<uint8_t>(byteVal));
	}
	return bytes;
}

BOOST_AUTO_TEST_CASE(EncryptedWireSinglePartTest)
{
	// Vector from body_encryption.json: body-vec-01-spec-example
	// password: "test123", salt: "1a2b3c4d5e6f7890abcdef1234567890", segmentIndex: 1
	// plaintext: "Hello World.txt\xff" (16 bytes)
	// ciphertext: 6a0d1eb225f844920540fa382ff68874
	// tag: 0cd77ce245a654463f90b945b1d22d5b
	std::string password = "test123";
	std::vector<uint8_t> salt = HexToBytesHelper("1a2b3c4d5e6f7890abcdef1234567890");
	std::vector<uint8_t> ct = HexToBytesHelper("6a0d1eb225f844920540fa382ff68874");
	std::vector<uint8_t> tag = HexToBytesHelper("0cd77ce245a654463f90b945b1d22d5b");
	std::vector<uint8_t> expectedPlaintext = HexToBytesHelper("48656c6c6f20576f726c642e747874ff");
	uint32_t segmentIndex = 1;

	// Build raw wire article:
	// line 1: =ybegin line=128 size=16 name=test.dat
	// line 2: =yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b
	// line 3: <yenc encoded ct>
	// line 4: =yend size=16 crc32=...
	// line 5: .
	YEncDecryptor encDec(password);
	std::string line1Plain = "=ybegin line=128 size=16 name=test.dat";
	std::vector<uint8_t> wireLine1;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line1Plain.data()), line1Plain.size(),
		segmentIndex, 1, true, salt.data(), wireLine1
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string line2Plain = "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b";
	std::vector<uint8_t> wireLine2;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line2Plain.data()), line2Plain.size(),
		segmentIndex, 2, false, salt.data(), wireLine2
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string wireLine3 = yEncEncode(std::string(reinterpret_cast<const char*>(ct.data()), ct.size()));

	// Calculate ciphertext CRC32
	Crc32 crc;
	crc.Append(ct.data(), ct.size());
	uint32_t ctCrc = crc.Finish();
	std::ostringstream endOss;
	endOss << "=yend size=16 crc32=" << std::hex << std::setw(8) << std::setfill('0') << ctCrc;
	std::string line4Plain = endOss.str();

	std::vector<uint8_t> wireLine4;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line4Plain.data()), line4Plain.size(),
		segmentIndex, 4, false, salt.data(), wireLine4
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string fullWire;
	fullWire.append(reinterpret_cast<const char*>(wireLine1.data()), wireLine1.size());
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine2.data()), wireLine2.size());
	fullWire.append("\r\n");
	fullWire.append(wireLine3);
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine4.data()), wireLine4.size());
	fullWire.append("\r\n.\r\n");

	// Test feed in chunks
	Decoder decoder;
	decoder.SetPassword(password.c_str());
	decoder.SetSegmentIndex(segmentIndex);
	decoder.SetCrcCheck(true);

	size_t chunkSize = 32;
	for (size_t offset = 0; offset < fullWire.size(); offset += chunkSize)
	{
		size_t n = std::min(chunkSize, fullWire.size() - offset);
		std::string chunk = fullWire.substr(offset, n);
		decoder.DecodeBuffer(chunk.data(), static_cast<int>(chunk.size()));
	}

	auto status = decoder.Check();
	BOOST_CHECK_EQUAL(static_cast<int>(status), static_cast<int>(Decoder::dsFinished));
	BOOST_CHECK_EQUAL(decoder.GetArticleFilename(), "test.dat");
	BOOST_CHECK(decoder.IsEncrypted());
	BOOST_CHECK_EQUAL(decoder.GetExpectedCrc(), ctCrc);
	BOOST_CHECK_EQUAL(decoder.GetCalculatedCrc(), ctCrc);

	const auto& pt = decoder.GetDecryptedData();
	BOOST_CHECK_EQUAL(pt.size(), expectedPlaintext.size());
	BOOST_CHECK_EQUAL_COLLECTIONS(pt.begin(), pt.end(), expectedPlaintext.begin(), expectedPlaintext.end());
}

BOOST_AUTO_TEST_CASE(EncryptedWireMultipartTest)
{
	std::string password = "test123";
	std::vector<uint8_t> salt = HexToBytesHelper("1a2b3c4d5e6f7890abcdef1234567890");
	std::vector<uint8_t> ct = HexToBytesHelper("6a0d1eb225f844920540fa382ff68874");
	std::vector<uint8_t> tag = HexToBytesHelper("0cd77ce245a654463f90b945b1d22d5b");
	std::vector<uint8_t> expectedPlaintext = HexToBytesHelper("48656c6c6f20576f726c642e747874ff");
	uint32_t segmentIndex = 1;

	// Multipart lines:
	// line 1: =ybegin part=1 total=2 line=128 size=32 name=multi.dat
	// line 2: =ypart begin=1 end=16
	// line 3: =yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b
	// line 4: <yenc encoded ct>
	// line 5: =yend size=16 part=1 pcrc32=...
	// line 6: .
	YEncDecryptor encDec(password);
	std::string line1Plain = "=ybegin part=1 total=2 line=128 size=32 name=multi.dat";
	std::vector<uint8_t> wireLine1;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line1Plain.data()), line1Plain.size(),
		segmentIndex, 1, true, salt.data(), wireLine1
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string line2Plain = "=ypart begin=1 end=16";
	std::vector<uint8_t> wireLine2;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line2Plain.data()), line2Plain.size(),
		segmentIndex, 2, false, salt.data(), wireLine2
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string line3Plain = "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b";
	std::vector<uint8_t> wireLine3;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line3Plain.data()), line3Plain.size(),
		segmentIndex, 3, false, salt.data(), wireLine3
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string wireLine4 = yEncEncode(std::string(reinterpret_cast<const char*>(ct.data()), ct.size()));

	Crc32 crc;
	crc.Append(ct.data(), ct.size());
	uint32_t ctCrc = crc.Finish();
	std::ostringstream endOss;
	endOss << "=yend size=16 part=1 pcrc32=" << std::hex << std::setw(8) << std::setfill('0') << ctCrc;
	std::string line5Plain = endOss.str();

	std::vector<uint8_t> wireLine5;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line5Plain.data()), line5Plain.size(),
		segmentIndex, 5, false, salt.data(), wireLine5
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string fullWire;
	fullWire.append(reinterpret_cast<const char*>(wireLine1.data()), wireLine1.size());
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine2.data()), wireLine2.size());
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine3.data()), wireLine3.size());
	fullWire.append("\r\n");
	fullWire.append(wireLine4);
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine5.data()), wireLine5.size());
	fullWire.append("\r\n.\r\n");

	Decoder decoder;
	decoder.SetPassword(password.c_str());
	decoder.SetSegmentIndex(segmentIndex);
	decoder.SetCrcCheck(true);

	size_t chunkSize = 25;
	for (size_t offset = 0; offset < fullWire.size(); offset += chunkSize)
	{
		size_t n = std::min(chunkSize, fullWire.size() - offset);
		std::string chunk = fullWire.substr(offset, n);
		decoder.DecodeBuffer(chunk.data(), static_cast<int>(chunk.size()));
	}

	auto status = decoder.Check();
	BOOST_CHECK_EQUAL(static_cast<int>(status), static_cast<int>(Decoder::dsFinished));
	BOOST_CHECK_EQUAL(decoder.GetArticleFilename(), "multi.dat");
	BOOST_CHECK_EQUAL(decoder.GetBeginPos(), 1);
	BOOST_CHECK_EQUAL(decoder.GetEndPos(), 16);
	BOOST_CHECK(decoder.IsEncrypted());
	BOOST_CHECK_EQUAL(decoder.GetExpectedCrc(), ctCrc);
	BOOST_CHECK_EQUAL(decoder.GetCalculatedCrc(), ctCrc);

	const auto& pt = decoder.GetDecryptedData();
	BOOST_CHECK_EQUAL(pt.size(), expectedPlaintext.size());
	BOOST_CHECK_EQUAL_COLLECTIONS(pt.begin(), pt.end(), expectedPlaintext.begin(), expectedPlaintext.end());
}

BOOST_AUTO_TEST_CASE(DecoderMissingSegmentIndexFailsClosedTest)
{
	std::string password = "test123";
	std::vector<uint8_t> salt = HexToBytesHelper("1a2b3c4d5e6f7890abcdef1234567890");
	std::vector<uint8_t> ct = HexToBytesHelper("6a0d1eb225f844920540fa382ff68874");
	uint32_t segmentIndex = 1;

	YEncDecryptor encDec(password);
	std::string line1Plain = "=ybegin line=128 size=16 name=test.dat";
	std::vector<uint8_t> wireLine1;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line1Plain.data()), line1Plain.size(),
		segmentIndex, 1, true, salt.data(), wireLine1
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string line2Plain = "=yencryption cipher=XChaCha20-Poly1305 salt=1a2b3c4d5e6f7890abcdef1234567890 tag=0cd77ce245a654463f90b945b1d22d5b";
	std::vector<uint8_t> wireLine2;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line2Plain.data()), line2Plain.size(),
		segmentIndex, 2, false, salt.data(), wireLine2
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string wireLine3 = yEncEncode(std::string(reinterpret_cast<const char*>(ct.data()), ct.size()));

	Crc32 crc;
	crc.Append(ct.data(), ct.size());
	uint32_t ctCrc = crc.Finish();
	std::ostringstream endOss;
	endOss << "=yend size=16 crc32=" << std::hex << std::setw(8) << std::setfill('0') << ctCrc;
	std::string line4Plain = endOss.str();

	std::vector<uint8_t> wireLine4;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line4Plain.data()), line4Plain.size(),
		segmentIndex, 4, false, salt.data(), wireLine4
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string fullWire;
	fullWire.append(reinterpret_cast<const char*>(wireLine1.data()), wireLine1.size());
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine2.data()), wireLine2.size());
	fullWire.append("\r\n");
	fullWire.append(wireLine3);
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine4.data()), wireLine4.size());
	fullWire.append("\r\n.\r\n");

	// Test with segmentIndex = 0 (missing segmentIndex)
	Decoder decoder;
	decoder.SetPassword(password.c_str());
	decoder.SetSegmentIndex(0); // explicitly zero
	decoder.SetCrcCheck(true);

	decoder.DecodeBuffer(fullWire.data(), static_cast<int>(fullWire.size()));

	auto checkStatus = decoder.Check();
	// Must fail closed with dsAuthFailed, dsNoBinaryData, or dsUnknownError
	BOOST_CHECK(checkStatus == Decoder::dsAuthFailed || checkStatus == Decoder::dsNoBinaryData || checkStatus == Decoder::dsUnknownError);
	BOOST_CHECK(decoder.GetDecryptedData().empty());
}

BOOST_AUTO_TEST_CASE(DecoderWireBufferCeilingTest)
{
	std::string password = "test123";
	std::vector<uint8_t> salt = HexToBytesHelper("1a2b3c4d5e6f7890abcdef1234567890");
	uint32_t segmentIndex = 1;

	YEncDecryptor encDec(password);
	std::string line1Plain = "=ybegin line=128 size=16 name=ceiling_test.dat";
	std::vector<uint8_t> wireLine1;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line1Plain.data()), line1Plain.size(),
		segmentIndex, 1, true, salt.data(), wireLine1
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	Decoder decoder;
	decoder.SetPassword(password.c_str());
	decoder.SetSegmentIndex(segmentIndex);

	std::string headerChunk(reinterpret_cast<const char*>(wireLine1.data()), wireLine1.size());
	headerChunk += "\r\n";
	decoder.DecodeBuffer(headerChunk.data(), static_cast<int>(headerChunk.size()));

	// Feed chunks exceeding 16 MiB without a dot terminator
	std::string junkChunk(1024 * 1024, 'A'); // 1 MiB chunk
	for (int i = 0; i < 17; ++i)
	{
		decoder.DecodeBuffer(junkChunk.data(), static_cast<int>(junkChunk.size()));
	}

	auto checkStatus = decoder.Check();
	BOOST_CHECK_EQUAL(static_cast<int>(checkStatus), static_cast<int>(Decoder::dsAuthFailed));
	BOOST_CHECK(decoder.GetDecryptedData().empty());
}

BOOST_AUTO_TEST_CASE(DecoderZeroLengthPayloadTest)
{
	std::string password = "test123";
	std::vector<uint8_t> salt = HexToBytesHelper("1a2b3c4d5e6f7890abcdef1234567890");
	uint32_t segmentIndex = 1;

	// Encrypt 0-byte plaintext
	YEncDecryptor encDec(password);
	std::vector<uint8_t> emptyPlain;
	uint8_t nonce[24];
	BOOST_REQUIRE(encDec.EnsureMasterKey(salt.data()));
	BOOST_REQUIRE(encDec.DeriveBodyNonce(segmentIndex, nonce));

	uint8_t tag[16];
	unsigned long long clen = 0;
	std::vector<uint8_t> ctAndTag(16);
	crypto_aead_xchacha20poly1305_ietf_encrypt(
		ctAndTag.data(), &clen,
		nullptr, 0,
		nullptr, 0,
		nullptr,
		nonce, encDec.GetMasterKey()
	);
	memcpy(tag, ctAndTag.data(), 16);

	std::string line1Plain = "=ybegin line=128 size=0 name=empty.dat";
	std::vector<uint8_t> wireLine1;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line1Plain.data()), line1Plain.size(),
		segmentIndex, 1, true, salt.data(), wireLine1
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string line2Plain = "=yencryption cipher=XChaCha20-Poly1305 salt=" +
		BytesToHexHelper(salt.data(), 16) + " tag=" + BytesToHexHelper(tag, 16);
	std::vector<uint8_t> wireLine2;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line2Plain.data()), line2Plain.size(),
		segmentIndex, 2, false, salt.data(), wireLine2
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string line3Plain = "=yend size=0 crc32=00000000";
	std::vector<uint8_t> wireLine3;
	BOOST_REQUIRE_EQUAL(static_cast<int>(encDec.EncryptControlLine(
		reinterpret_cast<const uint8_t*>(line3Plain.data()), line3Plain.size(),
		segmentIndex, 3, false, salt.data(), wireLine3
	)), static_cast<int>(YEncDecryptor::Status::Ok));

	std::string fullWire;
	fullWire.append(reinterpret_cast<const char*>(wireLine1.data()), wireLine1.size());
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine2.data()), wireLine2.size());
	fullWire.append("\r\n");
	fullWire.append(reinterpret_cast<const char*>(wireLine3.data()), wireLine3.size());
	fullWire.append("\r\n.\r\n");

	Decoder decoder;
	decoder.SetPassword(password.c_str());
	decoder.SetSegmentIndex(segmentIndex);
	decoder.SetCrcCheck(false);

	decoder.DecodeBuffer(fullWire.data(), static_cast<int>(fullWire.size()));

	auto status = decoder.Check();
	BOOST_CHECK_EQUAL(static_cast<int>(status), static_cast<int>(Decoder::dsFinished));
	BOOST_CHECK(decoder.IsEncrypted());
	BOOST_CHECK(decoder.GetDecryptedData().empty());
}

BOOST_AUTO_TEST_SUITE_END()
