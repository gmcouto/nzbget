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
#include "YEncKeyCache.h"

#include <sodium.h>
#include <algorithm>

YEncKeyCache::~YEncKeyCache()
{
	Clear();
}

bool YEncKeyCache::GetKey(const uint8_t salt[16], uint8_t outKey[32], const std::string& password)
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	uint8_t passwordHash[32];
	crypto_hash_sha256(passwordHash, reinterpret_cast<const unsigned char*>(password.data()), password.size());
	for (Entry& entry : m_entries)
	{
		if (memcmp(entry.salt, salt, 16) == 0 && memcmp(entry.passwordHash, passwordHash, 32) == 0)
		{
			memcpy(outKey, entry.key, 32);
			return true;
		}
	}
	return false;
}

void YEncKeyCache::PutKey(const uint8_t salt[16], const uint8_t key[32], const std::string& password)
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	uint8_t passwordHash[32];
	crypto_hash_sha256(passwordHash, reinterpret_cast<const unsigned char*>(password.data()), password.size());
	for (Entry& entry : m_entries)
	{
		if (memcmp(entry.salt, salt, 16) == 0 && memcmp(entry.passwordHash, passwordHash, 32) == 0)
		{
			memcpy(entry.key, key, 32);
			return;
		}
	}

	if (m_entries.size() >= MAX_CACHED_SALTS)
	{
		// Evict the oldest entry, zeroizing its key material
		sodium_memzero(m_entries.front().key, 32);
		sodium_memzero(m_entries.front().passwordHash, 32);
		m_entries.erase(m_entries.begin());
	}

	Entry entry;
	memcpy(entry.salt, salt, 16);
	memcpy(entry.passwordHash, passwordHash, 32);
	memcpy(entry.key, key, 32);
	m_entries.push_back(entry);
}

void YEncKeyCache::Clear()
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	for (Entry& entry : m_entries)
	{
		sodium_memzero(entry.key, 32);
		sodium_memzero(entry.passwordHash, 32);
	}
	m_entries.clear();
}


// The recursive lock keeps lookup, KDF and insertion one atomic operation.
bool YEncKeyCache::GetOrDeriveKey(const uint8_t salt[16], const std::string& password,
	uint8_t outKey[32], const std::function<bool(uint8_t*)>& derive)
{
	std::lock_guard<std::recursive_mutex> lock(m_mutex);
	if (GetKey(salt, outKey, password))
	{
		return true;
	}
	if (!derive(outKey))
	{
		sodium_memzero(outKey, 32);
		return false;
	}
	PutKey(salt, outKey, password);
	return true;
}
