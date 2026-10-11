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

#ifdef NZBGET_TESTING_HOOKS

#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <cstring>
#include <cmath>
#include <algorithm>
#include <stdexcept>
#include <memory>
#include <vector>

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
	ScopedBignum val(BN_dup(inBn));
	if (!val)
	{
		throw std::bad_alloc();
	}
	for (int i = 0; i < m; ++i)
	{
		BN_ULONG rem = BN_div_word(val.get(), radix);
		res[m - 1 - i] = static_cast<uint8_t>(rem);
	}
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

static std::vector<uint8_t> Ff1EncryptNumerals(
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

	ScopedBnCtx bnCtx(BN_CTX_new());
	if (!bnCtx)
	{
		throw std::bad_alloc();
	}
	BN_CTX_start(bnCtx.get());

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

	BIGNUM* bnNumB = BN_CTX_get(bnCtx.get());
	BIGNUM* bnNumA = BN_CTX_get(bnCtx.get());
	BIGNUM* bnY = BN_CTX_get(bnCtx.get());
	BIGNUM* bnMod = BN_CTX_get(bnCtx.get());
	BIGNUM* bnRadix = BN_CTX_get(bnCtx.get());
	BIGNUM* bnC = BN_CTX_get(bnCtx.get());
	BIGNUM* bnM = BN_CTX_get(bnCtx.get());
	if (!bnNumB || !bnNumA || !bnY || !bnMod || !bnRadix || !bnC || !bnM)
	{
		return {};
	}
	BN_set_word(bnRadix, radix);

	for (int i = 0; i < 10; ++i)
	{
		NumRadix(B, radix, bnNumB, bnCtx.get());
		std::vector<uint8_t> numBBytes(b, 0);
		BN_bn2binpad(bnNumB, numBBytes.data(), b);

		std::vector<uint8_t> q = qPrefix;
		q.push_back(static_cast<uint8_t>(i));
		q.insert(q.end(), numBBytes.begin(), numBBytes.end());

		std::vector<uint8_t> pq = p;
		pq.insert(pq.end(), q.begin(), q.end());

		std::vector<uint8_t> R = CbcMac(aesCtx.get(), pq);
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
			AesEcbEncrypt(aesCtx.get(), blk, encBlk);
			S.insert(S.end(), encBlk, encBlk + 16);
			j++;
		}

		BN_bin2bn(S.data(), d, bnY);
		int m = (i % 2 == 0) ? u : v;

		BN_set_word(bnM, m);
		BN_exp(bnMod, bnRadix, bnM, bnCtx.get());

		NumRadix(A, radix, bnNumA, bnCtx.get());

		BN_add(bnC, bnNumA, bnY);
		BN_nnmod(bnC, bnC, bnMod, bnCtx.get());

		std::vector<uint8_t> C = StrRadix(bnC, radix, m, bnCtx.get());
		A = B;
		B = C;
	}

	std::vector<uint8_t> result = A;
	result.insert(result.end(), B.begin(), B.end());

	return result;
}

} // anonymous namespace

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
	if (plainLen < 2)
	{
		return Status::Error;
	}
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
		if (cipherNumerals.size() != plainNumerals.size())
		{
			outWireData.clear();
			sodium_memzero(encKey, sizeof(encKey));
			sodium_memzero(tweak, sizeof(tweak));
			return Status::Error;
		}
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

#endif // NZBGET_TESTING_HOOKS
