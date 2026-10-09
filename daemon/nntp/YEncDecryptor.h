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

#ifndef YENC_DECRYPTOR_H
#define YENC_DECRYPTOR_H

#include <vector>
#include <string>
#include <cstdint>
#include <cstddef>
#include <cstring>

class YEncDecryptor
{
public:
	enum class Status
	{
		Ok,
		AuthFailed,
		MalformedHeader,
		NotEncrypted,
		Error
	};

	explicit YEncDecryptor(const std::string& password = "");
	~YEncDecryptor();

	void SetPassword(const std::string& password);
	const std::string& GetPassword() const { return m_password; }

	// Derives master key via Argon2id (RFC 9106: time=1, mem=64MB, parallelism=4, len=32),
	// caching in memory by 16-byte salt.
	bool EnsureMasterKey(const uint8_t salt[16]);

	// Derives 24-byte body nonce using HMAC-SHA256 with 19-byte message layout:
	// "yenc-body nonce" (15 bytes) + uint32_be(segmentIndex) (4 bytes)
	bool DeriveBodyNonce(uint32_t segmentIndex, uint8_t outNonce[24]);

	// Derives control key (32 bytes) and tweak (8 bytes) for FF1:
	// key = HMAC-SHA256(masterKey, "yenc-control key")
	// tweak = HMAC-SHA256(masterKey, "yenc-control tweak" + uint32_be(segmentIndex) + uint32_be(lineIndex))[:8]
	bool DeriveControlKeyAndTweak(uint32_t segmentIndex, uint32_t lineIndex, uint8_t outKey[32], uint8_t outTweak[8]);

	void SetMasterKeyForTesting(const uint8_t key[32], const uint8_t salt[16] = nullptr);

	// Authenticate and decrypt ciphertext using XChaCha20-Poly1305.
	// On tag mismatch, returns Status::AuthFailed and clears outPlaintext (Zero-Output Guarantee).
	Status AuthenticateAndDecrypt(
		const uint8_t* ciphertext,
		size_t cipherLen,
		const uint8_t salt[16],
		const uint8_t tag[16],
		uint32_t segmentIndex,
		std::vector<uint8_t>& outPlaintext
	);

	// Decrypt control line using Radix-253 FF1.
	// If isLine1 == true, extracts 20-byte bootstrap ([16B salt][4B uint32_be(segmentIndex)])
	// from the wire data prefix and decrypts the remainder.
	Status DecryptControlLine(
		const uint8_t* wireData,
		size_t wireLen,
		uint32_t segmentIndex,
		uint32_t lineIndex,
		bool isLine1,
		std::vector<uint8_t>& outPlaintext,
		std::vector<uint8_t>* outSalt = nullptr,
		uint32_t* outSegmentIndex = nullptr
	);

	struct YEncryptionHeader
	{
		std::string cipher;
		std::string saltHex;
		std::string indexHex;
		std::string tagHex;
		std::vector<uint8_t> salt;
		std::vector<uint8_t> tag;
		uint32_t segmentIndex = 0;
	};

	static bool ParseYEncryption(
		const char* line,
		size_t lineLen,
		YEncryptionHeader& outHeader
	);

	static bool ParseYEncryption(
		const char* line,
		YEncryptionHeader& outHeader
	)
	{
		return ParseYEncryption(line, line ? strlen(line) : 0, outHeader);
	}

	// Static helper to parse =yencryption line
	static bool ParseYEncryption(
		const char* line,
		size_t lineLen,
		std::string& outCipher,
		uint8_t outSalt[16],
		uint8_t outTag[16]
	);

	static bool ParseYEncryption(
		const char* line,
		size_t lineLen,
		std::string& outCipher,
		uint8_t outSalt[16],
		uint8_t outTag[16],
		uint32_t& outSegmentIndex
	);

	bool RestoreControlLines(
		const char* wireBlock,
		size_t wireLen,
		uint32_t segmentIndex,
		std::string& outCleanBlock,
		std::vector<uint8_t>& outLine1Salt,
		YEncryptionHeader* outHeader = nullptr
	);

	bool RestoreControlLines(
		const char* wireBlock,
		size_t wireLen,
		std::string& outCleanBlock,
		std::vector<uint8_t>& outLine1Salt,
		YEncryptionHeader* outHeader = nullptr
	)
	{
		return RestoreControlLines(wireBlock, wireLen, 0, outCleanBlock, outLine1Salt, outHeader);
	}

	Status EncryptControlLine(
		const uint8_t* plainData,
		size_t plainLen,
		uint32_t segmentIndex,
		uint32_t lineIndex,
		bool isLine1,
		const uint8_t salt[16],
		std::vector<uint8_t>& outWireData
	);

	size_t GetCachedSaltCount() const { return m_cachedSalt.empty() ? 0 : 1; }
	const std::vector<uint8_t>& GetCachedMasterKey() const { return m_cachedMasterKey; }

private:
	std::string m_password;
	std::vector<uint8_t> m_cachedSalt;
	std::vector<uint8_t> m_cachedMasterKey; // 32 bytes, zeroized on destruction or reset

	void ClearMasterKey();
};

#endif // YENC_DECRYPTOR_H
