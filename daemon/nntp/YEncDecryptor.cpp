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
#include "YEncDecryptor.h"
#include "YEncKeyCache.h"
#include "Ff1Primitives.h"
#include "Log.h"

#include <sodium.h>
#include <argon2.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <cstring>
#include <cmath>
#include <algorithm>
#include <stdexcept>
#include <memory>

using Ff1::ByteToNumeral;
using Ff1::NumeralToByte;

namespace
{

struct EvpCipherCtxDeleter
{
	void operator()(EVP_CIPHER_CTX* ctx) const
	{
		if (ctx)
		{
			EVP_CIPHER_CTX_free(ctx);
		}
	}
};
using ScopedEvpCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

struct BnCtxDeleter
{
	void operator()(BN_CTX* ctx) const
	{
		if (ctx)
		{
			BN_CTX_end(ctx);
			BN_CTX_free(ctx);
		}
	}
};
using ScopedBnCtx = std::unique_ptr<BN_CTX, BnCtxDeleter>;

struct BignumDeleter
{
	void operator()(BIGNUM* bn) const
	{
		if (bn)
		{
			BN_free(bn);
		}
	}
};
using ScopedBignum = std::unique_ptr<BIGNUM, BignumDeleter>;

static bool IsStrictLowerHex(const char* s, size_t len)
{
	for (size_t i = 0; i < len; ++i)
	{
		char c = s[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
		{
			return false;
		}
	}
	return true;
}

// FF1 decrypt (NIST SP 800-38G §6, radix 253): runs the 10-round Feistel
// backwards using the shared round-PRF scaffolding from Ff1Primitives.h.
static std::vector<uint8_t> Ff1DecryptNumerals(
	const uint8_t key[32],
	const uint8_t* tweak, size_t tweakLen,
	const std::vector<uint8_t>& numerals,
	int radix = 253)
{
	ScopedEvpCipherCtx aesCtx(EVP_CIPHER_CTX_new());
	if (!aesCtx)
	{
		throw std::bad_alloc();
	}
	EVP_EncryptInit_ex(aesCtx.get(), EVP_aes_256_ecb(), nullptr, key, nullptr);
	EVP_CIPHER_CTX_set_padding(aesCtx.get(), 0);

	int n = static_cast<int>(numerals.size());
	int t = static_cast<int>(tweakLen);
	int u = n / 2;
	int v = n - u;

	std::vector<uint8_t> A(numerals.begin(), numerals.begin() + u);
	std::vector<uint8_t> B(numerals.begin() + u, numerals.end());

	for (int roundIdx = 0; roundIdx < 10; ++roundIdx)
	{
		int i = 9 - roundIdx;
		std::vector<uint8_t> S = Ff1::RoundPrf(aesCtx.get(), radix, n, t, u, v,
			tweak, A, i);
		int d = static_cast<int>(S.size());
		BIGNUM* bnY = BN_bin2bn(S.data(), d, nullptr);
		BIGNUM* bnNumB = BN_new();
		BIGNUM* bnMod = BN_new();
		BIGNUM* bnC = BN_new();
		BN_CTX* ctx = BN_CTX_new();
		int m = (i % 2 == 0) ? u : v;
		Ff1::NumRadix(B, radix, bnNumB, ctx);
		BIGNUM* bnRadix = BN_new();
		BN_set_word(bnRadix, radix);
		BN_set_word(bnMod, m);
		BN_exp(bnMod, bnRadix, bnMod, ctx);
		BN_sub(bnC, bnNumB, bnY);
		BN_nnmod(bnC, bnC, bnMod, ctx);
		std::vector<uint8_t> C = Ff1::StrRadix(bnC, radix, m, ctx);
		BN_free(bnY);
		BN_free(bnNumB);
		BN_free(bnMod);
		BN_free(bnC);
		BN_free(bnRadix);
		BN_CTX_free(ctx);
		B = A;
		A = C;
	}

	std::vector<uint8_t> result = A;
	result.insert(result.end(), B.begin(), B.end());
	return result;
}

static bool HexToBytesStrict(const char* hex, size_t hexLen, uint8_t* outBytes, size_t outLen)
{
	if (hexLen != outLen * 2)
	{
		return false;
	}
	if (!IsStrictLowerHex(hex, hexLen))
	{
		return false;
	}
	for (size_t i = 0; i < outLen; ++i)
	{
		auto hexVal = [](char c) -> int {
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'a' && c <= 'f') return c - 'a' + 10;
			return -1;
		};
		int hi = hexVal(hex[i * 2]);
		int lo = hexVal(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0)
		{
			return false;
		}
		outBytes[i] = static_cast<uint8_t>((hi << 4) | lo);
	}
	return true;
}

} // anonymous namespace

YEncDecryptor::YEncDecryptor(const std::string& password, YEncKeyCache* keyCache)
	: m_password(password)
	, m_keyCache(keyCache)
{
	// A libsodium initialization failure is a hard crypto error, not a
	// condition to silently continue from — every subsequent AEAD/FF1 call
	// would misbehave. Record it as a typed failure consumed by the Status
	// surface (Error) instead of being swallowed.
	m_sodiumInitFailed = sodium_init() < 0;
	if (m_sodiumInitFailed)
	{
		error("Failed to initialize libsodium (sodium_init() < 0); decryption is unavailable");
	}
}

YEncDecryptor::~YEncDecryptor()
{
	ClearMasterKey();
}

void YEncDecryptor::ClearMasterKey()
{
	if (!m_cachedMasterKey.empty())
	{
		sodium_memzero(m_cachedMasterKey.data(), m_cachedMasterKey.size());
		m_cachedMasterKey.clear();
	}
	m_cachedSalt.clear();
}

bool YEncDecryptor::EnsureMasterKey(const uint8_t salt[16])
{
	if (!m_cachedSalt.empty() && m_cachedSalt.size() == 16 && memcmp(m_cachedSalt.data(), salt, 16) == 0)
	{
		return true;
	}

	if (m_password.empty())
	{
		return false;
	}

	ClearMasterKey();

	// Check job-owned key cache first
	if (m_keyCache)
	{
		uint8_t cachedKey[32];
		if (m_keyCache->GetKey(salt, cachedKey))
		{
			m_cachedSalt.assign(salt, salt + 16);
			m_cachedMasterKey.assign(cachedKey, cachedKey + 32);
			sodium_memzero(cachedKey, sizeof(cachedKey));
			return true;
		}
	}

	uint8_t key[32];
	int res = argon2id_hash_raw(1, 65536, 4, m_password.data(), m_password.size(), salt, 16, key, 32);
	if (res != ARGON2_OK)
	{
		return false;
	}

	if (m_keyCache)
	{
		m_keyCache->PutKey(salt, key);
	}

	m_cachedSalt.assign(salt, salt + 16);
	m_cachedMasterKey.assign(key, key + 32);
	sodium_memzero(key, sizeof(key));
	return true;
}

bool YEncDecryptor::DeriveBodyNonce(uint32_t segmentIndex, uint8_t outNonce[24])
{
	if (m_cachedMasterKey.size() != 32)
	{
		return false;
	}

	uint8_t msg[19];
	memcpy(msg, "yenc-body nonce", 15);
	msg[15] = static_cast<uint8_t>((segmentIndex >> 24) & 0xFF);
	msg[16] = static_cast<uint8_t>((segmentIndex >> 16) & 0xFF);
	msg[17] = static_cast<uint8_t>((segmentIndex >> 8) & 0xFF);
	msg[18] = static_cast<uint8_t>(segmentIndex & 0xFF);

	unsigned int mdLen = 0;
	uint8_t md[EVP_MAX_MD_SIZE];
	HMAC(EVP_sha256(), m_cachedMasterKey.data(), 32, msg, 19, md, &mdLen);
	memcpy(outNonce, md, 24);
	sodium_memzero(md, sizeof(md));
	return true;
}

bool YEncDecryptor::DeriveControlKeyAndTweak(uint32_t segmentIndex, uint32_t lineIndex, uint8_t outKey[32], uint8_t outTweak[8])
{
	if (m_cachedMasterKey.size() != 32)
	{
		return false;
	}

	unsigned int mdLen = 0;
	uint8_t md[EVP_MAX_MD_SIZE];
	HMAC(EVP_sha256(), m_cachedMasterKey.data(), 32, reinterpret_cast<const unsigned char*>("yenc-control key"), 16, md, &mdLen);
	memcpy(outKey, md, 32);

	uint8_t tweakMsg[26];
	memcpy(tweakMsg, "yenc-control tweak", 18);
	tweakMsg[18] = static_cast<uint8_t>((segmentIndex >> 24) & 0xFF);
	tweakMsg[19] = static_cast<uint8_t>((segmentIndex >> 16) & 0xFF);
	tweakMsg[20] = static_cast<uint8_t>((segmentIndex >> 8) & 0xFF);
	tweakMsg[21] = static_cast<uint8_t>(segmentIndex & 0xFF);
	tweakMsg[22] = static_cast<uint8_t>((lineIndex >> 24) & 0xFF);
	tweakMsg[23] = static_cast<uint8_t>((lineIndex >> 16) & 0xFF);
	tweakMsg[24] = static_cast<uint8_t>((lineIndex >> 8) & 0xFF);
	tweakMsg[25] = static_cast<uint8_t>(lineIndex & 0xFF);

	HMAC(EVP_sha256(), m_cachedMasterKey.data(), 32, tweakMsg, 26, md, &mdLen);
	memcpy(outTweak, md, 8);
	sodium_memzero(md, sizeof(md));
	return true;
}

YEncDecryptor::Status YEncDecryptor::AuthenticateAndDecrypt(
	const uint8_t* ciphertext,
	size_t cipherLen,
	const uint8_t salt[16],
	const uint8_t tag[16],
	uint32_t segmentIndex,
	const uint8_t* aad,
	size_t aadLen,
	std::vector<uint8_t>& outPlaintext)
{
	outPlaintext.clear();

	// A sodium_init() failure recorded at construction surfaces as a
	// typed Error on the first crypto call instead of undefined behavior.
	if (m_sodiumInitFailed)
	{
		return Status::Error;
	}

	if (!EnsureMasterKey(salt))
	{
		return Status::Error;
	}

	uint8_t nonce[24];
	if (!DeriveBodyNonce(segmentIndex, nonce))
	{
		return Status::Error;
	}

	std::vector<uint8_t> ctAndTag(cipherLen + 16);
	if (cipherLen > 0 && ciphertext != nullptr)
	{
		memcpy(ctAndTag.data(), ciphertext, cipherLen);
	}
	memcpy(ctAndTag.data() + cipherLen, tag, 16);

	outPlaintext.resize(cipherLen);
	unsigned long long decryptedLen = 0;
	int res = crypto_aead_xchacha20poly1305_ietf_decrypt(
		outPlaintext.data(), &decryptedLen,
		nullptr,
		ctAndTag.data(), ctAndTag.size(),
		aad, aadLen,
		nonce, m_cachedMasterKey.data());

	sodium_memzero(ctAndTag.data(), ctAndTag.size());
	sodium_memzero(nonce, sizeof(nonce));

	if (res != 0)
	{
		sodium_memzero(outPlaintext.data(), outPlaintext.size());
		outPlaintext.clear();
		return Status::AuthFailed;
	}

	outPlaintext.resize(decryptedLen);
	return Status::Ok;
}

std::vector<uint8_t> YEncDecryptor::BuildAad(
	const std::string& name,
	uint32_t partNumber,
	uint32_t partBegin,
	uint64_t segmentBytes)
{
	// Exact AAD serialization (Body Standard Section 2.1):
	// "yenc-body aad" (13B) + uint32_be(partNumber) (4B) + uint32_be(partBegin) (4B)
	// + uint64_be(segmentBytes) (8B) + uint32_be(nameLength) (4B) + nameBytes
	if (name.empty())
	{
		return {};
	}
	std::vector<uint8_t> aad;
	aad.reserve(33 + name.size());
	const char prefix[] = "yenc-body aad";
	aad.insert(aad.end(), reinterpret_cast<const uint8_t*>(prefix), reinterpret_cast<const uint8_t*>(prefix) + 13);

	aad.push_back(static_cast<uint8_t>((partNumber >> 24) & 0xFF));
	aad.push_back(static_cast<uint8_t>((partNumber >> 16) & 0xFF));
	aad.push_back(static_cast<uint8_t>((partNumber >> 8) & 0xFF));
	aad.push_back(static_cast<uint8_t>(partNumber & 0xFF));

	aad.push_back(static_cast<uint8_t>((partBegin >> 24) & 0xFF));
	aad.push_back(static_cast<uint8_t>((partBegin >> 16) & 0xFF));
	aad.push_back(static_cast<uint8_t>((partBegin >> 8) & 0xFF));
	aad.push_back(static_cast<uint8_t>(partBegin & 0xFF));

	for (int shift = 56; shift >= 0; shift -= 8)
	{
		aad.push_back(static_cast<uint8_t>((segmentBytes >> shift) & 0xFF));
	}

	uint32_t nameLen = static_cast<uint32_t>(name.size());
	aad.push_back(static_cast<uint8_t>((nameLen >> 24) & 0xFF));
	aad.push_back(static_cast<uint8_t>((nameLen >> 16) & 0xFF));
	aad.push_back(static_cast<uint8_t>((nameLen >> 8) & 0xFF));
	aad.push_back(static_cast<uint8_t>(nameLen & 0xFF));

	aad.insert(aad.end(), reinterpret_cast<const uint8_t*>(name.data()), reinterpret_cast<const uint8_t*>(name.data()) + name.size());
	return aad;
}

YEncDecryptor::Status YEncDecryptor::DecryptControlLine(
	const uint8_t* wireData,
	size_t wireLen,
	uint32_t segmentIndex,
	uint32_t lineIndex,
	bool isLine1,
	std::vector<uint8_t>& outPlaintext,
	std::vector<uint8_t>* outSalt,
	uint32_t* outSegmentIndex)
{
	outPlaintext.clear();

	if (m_sodiumInitFailed)
	{
		return Status::Error;
	}

	const uint8_t* ctBytes = wireData;
	size_t ctLen = wireLen;
	uint32_t effectiveSegmentIndex = segmentIndex;

	if (isLine1)
	{
		// 16B salt + 4B uint32_be(segmentIndex) + at least 2B FF1 ciphertext = 22 bytes minimum
		if (wireLen < 22)
		{
			return Status::Error;
		}
		const uint8_t* salt = wireData;
		for (size_t i = 0; i < 16; ++i)
		{
			if (salt[i] == 0x00 || salt[i] == 0x0A || salt[i] == 0x0D)
			{
				return Status::Error;
			}
		}

		uint32_t extractedIndex =
			(static_cast<uint32_t>(wireData[16]) << 24) |
			(static_cast<uint32_t>(wireData[17]) << 16) |
			(static_cast<uint32_t>(wireData[18]) << 8) |
			static_cast<uint32_t>(wireData[19]);

		if (extractedIndex == 0)
		{
			return Status::Error;
		}

		// Index framing rule (Body Std v1.2 §8): any uint32_be(segmentIndex) byte
		// 0x0A/0x0D would split Line 1 on the wire. Reject the bootstrap instead of decrypting.
		if (wireData[16] == 0x0A || wireData[16] == 0x0D ||
			wireData[17] == 0x0A || wireData[17] == 0x0D ||
			wireData[18] == 0x0A || wireData[18] == 0x0D ||
			wireData[19] == 0x0A || wireData[19] == 0x0D)
		{
			error("Bootstrap extraction failed: FORBIDDEN_SEGMENT_INDEX_BYTE");
			return Status::Error;
		}

		if (outSalt)
		{
			outSalt->assign(salt, salt + 16);
		}
		if (outSegmentIndex)
		{
			*outSegmentIndex = extractedIndex;
		}
		if (!EnsureMasterKey(salt))
		{
			return Status::Error;
		}

		effectiveSegmentIndex = extractedIndex;
		ctBytes = wireData + 20;
		ctLen = wireLen - 20;
	}
	else
	{
		if (wireLen < 2)
		{
			return Status::Error;
		}
		if (m_cachedMasterKey.empty())
		{
			return Status::Error;
		}
	}

	if (ctLen < 2)
	{
		return Status::Error;
	}

	uint8_t encKey[32];
	uint8_t tweak[8];
	if (!DeriveControlKeyAndTweak(effectiveSegmentIndex, lineIndex, encKey, tweak))
	{
		return Status::Error;
	}

	std::vector<uint8_t> ctNumerals;
	ctNumerals.reserve(ctLen);
	for (size_t i = 0; i < ctLen; ++i)
	{
		try
		{
			ctNumerals.push_back(ByteToNumeral(ctBytes[i]));
		}
		catch (...)
		{
			sodium_memzero(encKey, sizeof(encKey));
			return Status::Error;
		}
	}

	std::vector<uint8_t> ptNumerals;
	try
	{
		ptNumerals = Ff1DecryptNumerals(encKey, tweak, 8, ctNumerals, 253);
	}
	catch (...)
	{
		sodium_memzero(encKey, sizeof(encKey));
		return Status::Error;
	}
	sodium_memzero(encKey, sizeof(encKey));

	if (ptNumerals.size() != ctNumerals.size())
	{
		return Status::Error;
	}

	outPlaintext.reserve(ptNumerals.size());
	for (uint8_t n : ptNumerals)
	{
		try
		{
			outPlaintext.push_back(NumeralToByte(n));
		}
		catch (...)
		{
			outPlaintext.clear();
			return Status::Error;
		}
	}

	return Status::Ok;
}

bool YEncDecryptor::ParseYEncryption(
	const char* line,
	size_t lineLen,
	YEncryptionHeader& outHeader)
{
	if (!line || lineLen < 13)
	{
		return false;
	}
	while (lineLen > 0 && (line[lineLen - 1] == '\r' || line[lineLen - 1] == '\n'))
	{
		--lineLen;
	}

	std::vector<std::string_view> tokens;
	size_t start = 0;
	for (size_t i = 0; i <= lineLen; ++i)
	{
		if (i == lineLen || line[i] == ' ')
		{
			if (i == start)
			{
				return false;
			}
			tokens.emplace_back(line + start, i - start);
			start = i + 1;
		}
	}
	if (tokens.size() != 5 || tokens[0] != "=yencryption" || tokens[1] != "cipher=XChaCha20-Poly1305")
	{
		return false;
	}
	if (tokens[2].rfind("salt=", 0) != 0 || tokens[3].rfind("index=", 0) != 0 || tokens[4].rfind("tag=", 0) != 0)
	{
		return false;
	}
	const std::string_view saltHex = tokens[2].substr(5);
	const std::string_view indexHex = tokens[3].substr(6);
	const std::string_view tagHex = tokens[4].substr(4);
	if (saltHex.size() != 32 || indexHex.size() != 8 || tagHex.size() != 32 ||
		!IsStrictLowerHex(saltHex.data(), saltHex.size()) ||
		!IsStrictLowerHex(indexHex.data(), indexHex.size()) ||
		!IsStrictLowerHex(tagHex.data(), tagHex.size()))
	{
		return false;
	}

	uint32_t parsedIndex = 0;
	for (char c : indexHex)
	{
		parsedIndex = (parsedIndex << 4) | (c >= 'a' ? (c - 'a' + 10) : (c - '0'));
	}
	if (parsedIndex == 0)
	{
		return false;
	}
	// Index framing rule (Body Std v1.2 §8): reject any index whose
	// uint32_be bytes contain 0x0A or 0x0D (PROVIDER_FAILOVER).
	for (int shift = 24; shift >= 0; shift -= 8)
	{
		const uint8_t indexByte = static_cast<uint8_t>((parsedIndex >> shift) & 0xFF);
		if (indexByte == 0x0A || indexByte == 0x0D)
		{
			return false;
		}
	}

	outHeader.cipher = "XChaCha20-Poly1305";
	outHeader.saltHex = std::string(saltHex);
	outHeader.indexHex = std::string(indexHex);
	outHeader.tagHex = std::string(tagHex);
	outHeader.salt.resize(16);
	outHeader.tag.resize(16);
	outHeader.segmentIndex = parsedIndex;
	return HexToBytesStrict(saltHex.data(), saltHex.size(), outHeader.salt.data(), outHeader.salt.size()) &&
		HexToBytesStrict(tagHex.data(), tagHex.size(), outHeader.tag.data(), outHeader.tag.size());
}

bool YEncDecryptor::RestoreControlLines(
	const char* wireBlock,
	size_t wireLen,
	std::string& outCleanBlock,
	std::vector<uint8_t>& outLine1Salt,
	YEncryptionHeader* outHeader)
{
	// Header-loop semantics (Control Std v1.2 §5 step 4): this decoder uses
	// the structural-assumption approach — it decrypts the known control-line
	// positions (Line 1 =ybegin, optional =ypart, =yencryption, footer =yend)
	// instead of probing each middle line. For canonical producers this is
	// conformant: only decryption success yielding non-=y content would
	// terminate the header loop, and any structural mismatch (including a
	// misplaced =yencryption, see the placement vectors) fails closed here as
	// PROVIDER_FAILOVER — no FF1 error is ever passed through as a data line.
	outCleanBlock.clear();
	outLine1Salt.clear();
	if (!wireBlock || wireLen == 0)
	{
		return false;
	}

	struct WireLine
	{
		const char* data;
		size_t len;
		std::string_view ending;
	};
	std::vector<WireLine> lines;
	const char* cursor = wireBlock;
	const char* end = wireBlock + wireLen;
	while (cursor < end)
	{
		const char* searchStart = (lines.empty() && (end - cursor >= 20) && memcmp(cursor, "=y", 2) != 0) ? cursor + 20 : cursor;
		const char* newline = static_cast<const char*>(memchr(searchStart, '\n', end - searchStart));
		const char* lineEnd = newline ? newline : end;
		const bool crlf = lineEnd > cursor && lineEnd[-1] == '\r';
		lines.push_back({cursor, static_cast<size_t>((crlf ? lineEnd - 1 : lineEnd) - cursor),
			newline ? (crlf ? std::string_view("\r\n", 2) : std::string_view("\n", 1)) : std::string_view()});
		cursor = newline ? newline + 1 : end;
	}
	while (!lines.empty() && lines.back().len == 0)
	{
		lines.pop_back();
	}
	if (!lines.empty() && lines.back().len == 1 && lines.back().data[0] == '.')
	{
		lines.pop_back();
	}
	while (!lines.empty() && lines.back().len == 0)
	{
		lines.pop_back();
	}
	if (lines.size() < 3)
	{
		return false;
	}

	std::vector<uint8_t> restored;
	uint32_t line1SegmentIndex = 0;
	if (DecryptControlLine(reinterpret_cast<const uint8_t*>(lines[0].data), lines[0].len,
		0, 1, true, restored, &outLine1Salt, &line1SegmentIndex) != Status::Ok ||
		restored.size() < 8 || memcmp(restored.data(), "=ybegin ", 8) != 0 ||
		line1SegmentIndex == 0)
	{
		return false;
	}

	const std::string begin(restored.begin(), restored.end());
	outCleanBlock.append(begin).append(lines[0].ending);
	const bool multipart = begin.find(" part=") != std::string::npos;
	const size_t headerIndex = multipart ? 2 : 1;
	if (multipart)
	{
		if (lines.size() < 4 || DecryptControlLine(reinterpret_cast<const uint8_t*>(lines[1].data), lines[1].len,
			line1SegmentIndex, 2, false, restored) != Status::Ok || restored.size() < 7 ||
			memcmp(restored.data(), "=ypart ", 7) != 0)
		{
			return false;
		}
		outCleanBlock.append(reinterpret_cast<const char*>(restored.data()), restored.size()).append(lines[1].ending);
	}

	YEncryptionHeader header;
	if (DecryptControlLine(reinterpret_cast<const uint8_t*>(lines[headerIndex].data), lines[headerIndex].len,
		line1SegmentIndex, static_cast<uint32_t>(headerIndex + 1), false, restored) != Status::Ok ||
		!ParseYEncryption(reinterpret_cast<const char*>(restored.data()), restored.size(), header))
	{
		outCleanBlock.clear();
		outLine1Salt.clear();
		return false;
	}

	// Enforce Dual-Bootstrap Agreement
	if (header.salt != outLine1Salt || header.segmentIndex != line1SegmentIndex)
	{
		outCleanBlock.clear();
		outLine1Salt.clear();
		return false;
	}

	for (size_t i = headerIndex + 1; i + 1 < lines.size(); ++i)
	{
		if (lines[i].len >= 13 && memcmp(lines[i].data, "=yencryption ", 13) == 0)
		{
			return false;
		}
		outCleanBlock.append(lines[i].data, lines[i].len).append(lines[i].ending);
	}

	const size_t footerIndex = lines.size() - 1;
	if (DecryptControlLine(reinterpret_cast<const uint8_t*>(lines[footerIndex].data), lines[footerIndex].len,
		line1SegmentIndex, static_cast<uint32_t>(lines.size()), false, restored) != Status::Ok ||
		restored.size() < 5 || memcmp(restored.data(), "=yend", 5) != 0)
	{
		return false;
	}
	outCleanBlock.append(reinterpret_cast<const char*>(restored.data()), restored.size()).append(lines[footerIndex].ending);
	if (outHeader)
	{
		*outHeader = std::move(header);
	}
	return true;
}
