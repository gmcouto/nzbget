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

#include <sodium.h>
#include <argon2.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <cstring>
#include <cmath>
#include <algorithm>
#include <stdexcept>

namespace
{

static uint8_t ByteToNumeral(uint8_t b)
{
	if (b >= 0x01 && b <= 0x09) return b - 1;
	if (b == 0x0B) return 9;
	if (b == 0x0C) return 10;
	if (b >= 0x0E) return b - 3;
	throw std::runtime_error("Forbidden byte outside 253-byte Alphabet");
}

static uint8_t NumeralToByte(uint8_t num)
{
	if (num <= 8) return num + 1;
	if (num == 9) return 0x0B;
	if (num == 10) return 0x0C;
	if (num <= 252) return num + 3;
	throw std::runtime_error("Numeral out of range [0, 252]");
}

static void NumRadix(const std::vector<uint8_t>& numerals, int radix, BIGNUM* outBn, BN_CTX* ctx)
{
	BN_zero(outBn);
	for (uint8_t n : numerals)
	{
		BN_mul_word(outBn, radix);
		BN_add_word(outBn, n);
	}
}

static std::vector<uint8_t> StrRadix(const BIGNUM* inBn, int radix, int m, BN_CTX* ctx)
{
	std::vector<uint8_t> res(m, 0);
	BIGNUM* val = BN_dup(inBn);
	for (int i = 0; i < m; ++i)
	{
		BN_ULONG rem = BN_div_word(val, radix);
		res[m - 1 - i] = static_cast<uint8_t>(rem);
	}
	BN_free(val);
	return res;
}

static void AesEcbEncrypt(EVP_CIPHER_CTX* ctx, const uint8_t in[16], uint8_t out[16])
{
	int outl = 0;
	EVP_EncryptUpdate(ctx, out, &outl, in, 16);
}

static std::vector<uint8_t> CbcMac(EVP_CIPHER_CTX* ctx, const std::vector<uint8_t>& data)
{
	std::vector<uint8_t> block(16, 0);
	uint8_t tmp[16];
	for (size_t i = 0; i < data.size(); i += 16)
	{
		for (int k = 0; k < 16; ++k)
		{
			tmp[k] = block[k] ^ data[i + k];
		}
		AesEcbEncrypt(ctx, tmp, block.data());
	}
	return block;
}

static std::vector<uint8_t> Ff1DecryptNumerals(
	const uint8_t key[32],
	const uint8_t* tweak, size_t tweakLen,
	const std::vector<uint8_t>& numerals,
	int radix = 253)
{
	EVP_CIPHER_CTX* aesCtx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(aesCtx, EVP_aes_256_ecb(), nullptr, key, nullptr);
	EVP_CIPHER_CTX_set_padding(aesCtx, 0);

	BN_CTX* bnCtx = BN_CTX_new();
	BN_CTX_start(bnCtx);

	int n = static_cast<int>(numerals.size());
	int t = static_cast<int>(tweakLen);
	int u = n / 2;
	int v = n - u;
	int b = static_cast<int>(std::ceil(std::ceil(v * std::log2(static_cast<double>(radix))) / 8.0));
	int d = 4 * static_cast<int>(std::ceil(b / 4.0)) + 4;

	std::vector<uint8_t> p(16, 0);
	p[0] = 1; p[1] = 2; p[2] = 1;
	p[3] = (radix >> 16) & 0xFF;
	p[4] = (radix >> 8) & 0xFF;
	p[5] = radix & 0xFF;
	p[6] = 10;
	p[7] = u % 256;
	p[8] = (n >> 24) & 0xFF; p[9] = (n >> 16) & 0xFF; p[10] = (n >> 8) & 0xFF; p[11] = n & 0xFF;
	p[12] = (t >> 24) & 0xFF; p[13] = (t >> 16) & 0xFF; p[14] = (t >> 8) & 0xFF; p[15] = t & 0xFF;

	int padLen = ((-t - b - 1) % 16 + 16) % 16;
	std::vector<uint8_t> qPrefix;
	qPrefix.insert(qPrefix.end(), tweak, tweak + tweakLen);
	qPrefix.insert(qPrefix.end(), padLen, 0);

	std::vector<uint8_t> A(numerals.begin(), numerals.begin() + u);
	std::vector<uint8_t> B(numerals.begin() + u, numerals.end());

	BIGNUM* bnNumA = BN_CTX_get(bnCtx);
	BIGNUM* bnNumB = BN_CTX_get(bnCtx);
	BIGNUM* bnY = BN_CTX_get(bnCtx);
	BIGNUM* bnMod = BN_CTX_get(bnCtx);
	BIGNUM* bnRadix = BN_CTX_get(bnCtx);
	BIGNUM* bnC = BN_CTX_get(bnCtx);
	BN_set_word(bnRadix, radix);

	for (int roundIdx = 0; roundIdx < 10; ++roundIdx)
	{
		int i = 9 - roundIdx;
		NumRadix(A, radix, bnNumA, bnCtx);
		std::vector<uint8_t> numABytes(b, 0);
		BN_bn2binpad(bnNumA, numABytes.data(), b);

		std::vector<uint8_t> q = qPrefix;
		q.push_back(static_cast<uint8_t>(i));
		q.insert(q.end(), numABytes.begin(), numABytes.end());

		std::vector<uint8_t> pq = p;
		pq.insert(pq.end(), q.begin(), q.end());

		std::vector<uint8_t> R = CbcMac(aesCtx, pq);
		std::vector<uint8_t> S = R;
		uint32_t j = 1;
		while (S.size() < static_cast<size_t>(d))
		{
			uint8_t jBytes[16] = {0};
			jBytes[12] = (j >> 24) & 0xFF;
			jBytes[13] = (j >> 16) & 0xFF;
			jBytes[14] = (j >> 8) & 0xFF;
			jBytes[15] = j & 0xFF;

			uint8_t blk[16];
			for (int k = 0; k < 16; ++k) blk[k] = R[k] ^ jBytes[k];
			uint8_t encBlk[16];
			AesEcbEncrypt(aesCtx, blk, encBlk);
			S.insert(S.end(), encBlk, encBlk + 16);
			j++;
		}

		BN_bin2bn(S.data(), d, bnY);
		int m = (i % 2 == 0) ? u : v;

		BIGNUM* bnM = BN_CTX_get(bnCtx);
		BN_set_word(bnM, m);
		BN_exp(bnMod, bnRadix, bnM, bnCtx);

		NumRadix(B, radix, bnNumB, bnCtx);

		BN_sub(bnC, bnNumB, bnY);
		BN_nnmod(bnC, bnC, bnMod, bnCtx);

		std::vector<uint8_t> C = StrRadix(bnC, radix, m, bnCtx);
		B = A;
		A = C;
	}

	std::vector<uint8_t> result = A;
	result.insert(result.end(), B.begin(), B.end());

	BN_CTX_end(bnCtx);
	BN_CTX_free(bnCtx);
	EVP_CIPHER_CTX_free(aesCtx);
	return result;
}

static std::vector<uint8_t> Ff1EncryptNumerals(
	const uint8_t key[32],
	const uint8_t* tweak, size_t tweakLen,
	const std::vector<uint8_t>& numerals,
	int radix = 253)
{
	EVP_CIPHER_CTX* aesCtx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(aesCtx, EVP_aes_256_ecb(), nullptr, key, nullptr);
	EVP_CIPHER_CTX_set_padding(aesCtx, 0);

	BN_CTX* bnCtx = BN_CTX_new();
	BN_CTX_start(bnCtx);

	int n = static_cast<int>(numerals.size());
	int t = static_cast<int>(tweakLen);
	int u = n / 2;
	int v = n - u;
	int b = static_cast<int>(std::ceil(std::ceil(v * std::log2(static_cast<double>(radix))) / 8.0));
	int d = 4 * static_cast<int>(std::ceil(b / 4.0)) + 4;

	std::vector<uint8_t> p(16, 0);
	p[0] = 1; p[1] = 2; p[2] = 1;
	p[3] = (radix >> 16) & 0xFF;
	p[4] = (radix >> 8) & 0xFF;
	p[5] = radix & 0xFF;
	p[6] = 10;
	p[7] = u % 256;
	p[8] = (n >> 24) & 0xFF; p[9] = (n >> 16) & 0xFF; p[10] = (n >> 8) & 0xFF; p[11] = n & 0xFF;
	p[12] = (t >> 24) & 0xFF; p[13] = (t >> 16) & 0xFF; p[14] = (t >> 8) & 0xFF; p[15] = t & 0xFF;

	int padLen = ((-t - b - 1) % 16 + 16) % 16;
	std::vector<uint8_t> qPrefix;
	qPrefix.insert(qPrefix.end(), tweak, tweak + tweakLen);
	qPrefix.insert(qPrefix.end(), padLen, 0);

	std::vector<uint8_t> A(numerals.begin(), numerals.begin() + u);
	std::vector<uint8_t> B(numerals.begin() + u, numerals.end());

	BIGNUM* bnNumB = BN_CTX_get(bnCtx);
	BIGNUM* bnNumA = BN_CTX_get(bnCtx);
	BIGNUM* bnY = BN_CTX_get(bnCtx);
	BIGNUM* bnMod = BN_CTX_get(bnCtx);
	BIGNUM* bnRadix = BN_CTX_get(bnCtx);
	BIGNUM* bnC = BN_CTX_get(bnCtx);
	BN_set_word(bnRadix, radix);

	for (int i = 0; i < 10; ++i)
	{
		NumRadix(B, radix, bnNumB, bnCtx);
		std::vector<uint8_t> numBBytes(b, 0);
		BN_bn2binpad(bnNumB, numBBytes.data(), b);

		std::vector<uint8_t> q = qPrefix;
		q.push_back(static_cast<uint8_t>(i));
		q.insert(q.end(), numBBytes.begin(), numBBytes.end());

		std::vector<uint8_t> pq = p;
		pq.insert(pq.end(), q.begin(), q.end());

		std::vector<uint8_t> R = CbcMac(aesCtx, pq);
		std::vector<uint8_t> S = R;
		uint32_t j = 1;
		while (S.size() < static_cast<size_t>(d))
		{
			uint8_t jBytes[16] = {0};
			jBytes[12] = (j >> 24) & 0xFF;
			jBytes[13] = (j >> 16) & 0xFF;
			jBytes[14] = (j >> 8) & 0xFF;
			jBytes[15] = j & 0xFF;

			uint8_t blk[16];
			for (int k = 0; k < 16; ++k) blk[k] = R[k] ^ jBytes[k];
			uint8_t encBlk[16];
			AesEcbEncrypt(aesCtx, blk, encBlk);
			S.insert(S.end(), encBlk, encBlk + 16);
			j++;
		}

		BN_bin2bn(S.data(), d, bnY);
		int m = (i % 2 == 0) ? u : v;

		BIGNUM* bnM = BN_CTX_get(bnCtx);
		BN_set_word(bnM, m);
		BN_exp(bnMod, bnRadix, bnM, bnCtx);

		NumRadix(A, radix, bnNumA, bnCtx);

		BN_add(bnC, bnNumA, bnY);
		BN_nnmod(bnC, bnC, bnMod, bnCtx);

		std::vector<uint8_t> C = StrRadix(bnC, radix, m, bnCtx);
		A = B;
		B = C;
	}

	std::vector<uint8_t> result = A;
	result.insert(result.end(), B.begin(), B.end());

	BN_CTX_end(bnCtx);
	BN_CTX_free(bnCtx);
	EVP_CIPHER_CTX_free(aesCtx);
	return result;
}

static bool HexToBytes(const char* hex, size_t hexLen, uint8_t* outBytes, size_t outLen)
{
	if (hexLen != outLen * 2)
	{
		return false;
	}
	for (size_t i = 0; i < outLen; ++i)
	{
		auto hexVal = [](char c) -> int {
			if (c >= '0' && c <= '9') return c - '0';
			if (c >= 'a' && c <= 'f') return c - 'a' + 10;
			if (c >= 'A' && c <= 'F') return c - 'A' + 10;
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

YEncDecryptor::YEncDecryptor(const std::string& password)
	: m_password(password)
{
	if (sodium_init() < 0)
	{
		// Failed to initialize libsodium
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

void YEncDecryptor::SetPassword(const std::string& password)
{
	m_password = password;
	ClearMasterKey();
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

	uint8_t key[32];
	int res = argon2id_hash_raw(1, 65536, 4, m_password.data(), m_password.size(), salt, 16, key, 32);
	if (res != ARGON2_OK)
	{
		return false;
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
	std::vector<uint8_t>& outPlaintext)
{
	outPlaintext.clear();

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
		nullptr, 0,
		nonce, m_cachedMasterKey.data());

	sodium_memzero(ctAndTag.data(), ctAndTag.size());
	sodium_memzero(nonce, sizeof(nonce));

	if (res != 0)
	{
		outPlaintext.clear();
		return Status::AuthFailed;
	}

	outPlaintext.resize(decryptedLen);
	return Status::Ok;
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

bool YEncDecryptor::ParseYEncryption(
	const char* line,
	size_t lineLen,
	std::string& outCipher,
	uint8_t outSalt[16],
	uint8_t outTag[16],
	uint32_t& outSegmentIndex)
{
	YEncryptionHeader header;
	if (!ParseYEncryption(line, lineLen, header))
	{
		return false;
	}
	outCipher = header.cipher;
	memcpy(outSalt, header.salt.data(), 16);
	memcpy(outTag, header.tag.data(), 16);
	outSegmentIndex = header.segmentIndex;
	return true;
}

bool YEncDecryptor::ParseYEncryption(
	const char* line,
	size_t lineLen,
	std::string& outCipher,
	uint8_t outSalt[16],
	uint8_t outTag[16])
{
	uint32_t dummyIndex = 0;
	return ParseYEncryption(line, lineLen, outCipher, outSalt, outTag, dummyIndex);
}

YEncDecryptor::Status YEncDecryptor::EncryptControlLine(
	const uint8_t* plainData,
	size_t plainLen,
	uint32_t segmentIndex,
	uint32_t lineIndex,
	bool isLine1,
	const uint8_t salt[16],
	std::vector<uint8_t>& outWireData)
{
	outWireData.clear();
	if (!EnsureMasterKey(salt))
	{
		return Status::Error;
	}

	uint8_t encKey[32];
	uint8_t tweak[8];
	if (!DeriveControlKeyAndTweak(segmentIndex, lineIndex, encKey, tweak))
	{
		return Status::Error;
	}

	std::vector<uint8_t> plainNumerals;
	plainNumerals.reserve(plainLen);
	try
	{
		for (size_t i = 0; i < plainLen; ++i)
		{
			plainNumerals.push_back(ByteToNumeral(plainData[i]));
		}
		const auto cipherNumerals = Ff1EncryptNumerals(encKey, tweak, 8, plainNumerals, 253);
		if (isLine1)
		{
			outWireData.insert(outWireData.end(), salt, salt + 16);
			outWireData.push_back(static_cast<uint8_t>((segmentIndex >> 24) & 0xff));
			outWireData.push_back(static_cast<uint8_t>((segmentIndex >> 16) & 0xff));
			outWireData.push_back(static_cast<uint8_t>((segmentIndex >> 8) & 0xff));
			outWireData.push_back(static_cast<uint8_t>(segmentIndex & 0xff));
		}
		for (uint8_t numeral : cipherNumerals)
		{
			outWireData.push_back(NumeralToByte(numeral));
		}
	}
	catch (...)
	{
		outWireData.clear();
		sodium_memzero(encKey, sizeof(encKey));
		sodium_memzero(tweak, sizeof(tweak));
		return Status::Error;
	}
	sodium_memzero(encKey, sizeof(encKey));
	sodium_memzero(tweak, sizeof(tweak));
	return Status::Ok;
}

bool YEncDecryptor::RestoreControlLines(
	const char* wireBlock,
	size_t wireLen,
	uint32_t segmentIndex,
	std::string& outCleanBlock,
	std::vector<uint8_t>& outLine1Salt,
	YEncryptionHeader* outHeader)
{
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
	if (!lines.empty() && lines.back().len == 1 && lines.back().data[0] == '.')
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
		segmentIndex, 1, true, restored, &outLine1Salt, &line1SegmentIndex) != Status::Ok ||
		restored.size() < 8 || memcmp(restored.data(), "=ybegin ", 8) != 0 ||
		line1SegmentIndex == 0)
	{
		return false;
	}
	if (segmentIndex > 0 && line1SegmentIndex != segmentIndex)
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
