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

#ifndef YENCKEYCACHE_H
#define YENCKEYCACHE_H

#include <cstdint>
#include <cstddef>
#include <mutex>
#include <vector>
#include <string>
#include <functional>

// Bounded thread-safe job-owned Argon2id master-key cache.
// Deriving a 64 MiB Argon2id key costs ~15 ms per article; a 1000-article
// encrypted release would otherwise repeat the identical KDF per article.
// The cache is owned by NzbInfo (one per download job) so parallel
// ArticleDownloader threads share derived keys for the same salt, and the
// keys are zeroized when the job's NzbInfo is destroyed.
class YEncKeyCache
{
public:
	// Maximum salts cached per job; a job typically has exactly one salt.
	static constexpr size_t MAX_CACHED_SALTS = 16;

	YEncKeyCache() = default;
	YEncKeyCache(const YEncKeyCache&) = delete;
	YEncKeyCache& operator=(const YEncKeyCache&) = delete;
	virtual ~YEncKeyCache();

	// Returns true and copies the 32-byte key if the salt is cached.
	bool GetKey(const uint8_t salt[16], uint8_t outKey[32], const std::string& password = "");

	// Inserts or updates the cached key for the salt; evicts (zeroizing) the
	// oldest entry when the cache is full.
	void PutKey(const uint8_t salt[16], const uint8_t key[32], const std::string& password = "");

	// Single-flight derivation; a password edit cannot reuse the old key.
	virtual bool GetOrDeriveKey(const uint8_t salt[16], const std::string& password,
		uint8_t outKey[32], const std::function<bool(uint8_t*)>& derive);

	// Zeroizes and drops all cached keys (password change / job teardown).
	void Clear();

#ifdef NZBGET_TESTING_HOOKS
	// Observe cache occupancy without exposing it in production.
	size_t Size() { std::lock_guard<std::recursive_mutex> lock(m_mutex); return m_entries.size(); }
#endif

private:
	struct Entry
	{
		uint8_t salt[16] = {0};
		uint8_t key[32] = {0};
		uint8_t passwordHash[32] = {0};
	};

	std::recursive_mutex m_mutex;
	std::vector<Entry> m_entries;
};

#endif // YENCKEYCACHE_H
