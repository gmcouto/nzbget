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

bool YEncKeyCache::GetKey(const uint8_t salt[16], uint8_t outKey[32])
{
	std::lock_guard<std::mutex> lock(m_mutex);
	for (Entry& entry : m_entries)
	{
		if (memcmp(entry.salt, salt, 16) == 0)
		{
			memcpy(outKey, entry.key, 32);
			return true;
		}
	}
	return false;
}

void YEncKeyCache::PutKey(const uint8_t salt[16], const uint8_t key[32])
{
	std::lock_guard<std::mutex> lock(m_mutex);
	for (Entry& entry : m_entries)
	{
		if (memcmp(entry.salt, salt, 16) == 0)
		{
			memcpy(entry.key, key, 32);
			return;
		}
	}

	if (m_entries.size() >= kMaxCachedSalts)
	{
		// Evict the oldest entry, zeroizing its key material
		sodium_memzero(m_entries.front().key, 32);
		m_entries.erase(m_entries.begin());
	}

	Entry entry;
	memcpy(entry.salt, salt, 16);
	memcpy(entry.key, key, 32);
	m_entries.push_back(entry);
}

void YEncKeyCache::Clear()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	for (Entry& entry : m_entries)
	{
		sodium_memzero(entry.key, 32);
	}
	m_entries.clear();
}

size_t YEncKeyCache::Size()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return m_entries.size();
}
