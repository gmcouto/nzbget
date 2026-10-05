/*
 *  This file is part of nzbget. See <https://nzbget.com>.
 *
 *  Copyright (C) 2007-2019 Andrey Prygunkov <hugbug@users.sourceforge.net>
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
#include "Decoder.h"
#include "Log.h"
#include "Util.h"
#include "YEncDecryptor.h"

Decoder::Decoder()
{
	Clear();
}

Decoder::~Decoder() = default;

void Decoder::SetPassword(const char* password)
{
	if (!m_decryptor)
	{
		m_ownDecryptor = std::make_unique<YEncDecryptor>(password ? password : "");
		m_decryptor = m_ownDecryptor.get();
	}
	else
	{
		m_decryptor->SetPassword(password ? password : "");
	}
}

void Decoder::Clear()
{
	m_format = efUnknown;
	m_articleFilename.clear();
	m_body = false;
	m_begin = false;
	m_part = false;
	m_end = false;
	m_crc = false;
	m_eof = false;
	m_expectedCRC = 0;
	m_crc32.Reset();
	m_beginPos = 0;
	m_endPos = 0;
	m_size = 0;
	m_endSize = 0;
	m_outSize = 0;
	m_state = 0;
	m_crcCheck = false;
	m_lineBuf.Reserve(1024*8);
	m_lineBuf.SetLength(0);
	m_encrypted = false;
	m_authFailed = false;
	m_cipher.clear();
	memset(m_salt, 0, sizeof(m_salt));
	memset(m_tag, 0, sizeof(m_tag));
	m_cipherPayload.clear();
	if (!m_decryptedPlaintext.empty())
	{
		sodium_memzero(m_decryptedPlaintext.data(), m_decryptedPlaintext.size());
		m_decryptedPlaintext.clear();
	}
	m_encryptedWireMode = false;
	m_wireProcessed = false;
	m_wireBuffer.clear();
}

/* At the beginning of article the processing goes line by line to find '=ybegin'-marker.
 * Once the yEnc-data is started switches to blockwise processing.
 * At the end of yEnc-data switches back to line by line mode to
 * process '=yend'-marker and EOF-marker.
 * UU-encoded articles are processed completely in line by line mode.
 */
int Decoder::DecodeBuffer(char* buffer, int len)
{
	if (m_rawMode)
	{
		ProcessRaw(buffer, len);
		return len;
	}

	bool alreadyBuffered = false;

	// Check if candidate for encrypted wire mode
	if (!m_wireProcessed && (m_encryptedWireMode || (m_format == efUnknown && m_decryptor && !m_decryptor->GetPassword().empty() && m_segmentIndex > 0)))
	{
		if (m_wireBuffer.size() + len > MAX_ENCRYPTED_WIRE_ARTICLE_SIZE)
		{
			m_authFailed = true;
			m_wireBuffer.clear();
			m_encryptedWireMode = false;
			return 0;
		}
		m_wireBuffer.append(buffer, len);

		if (!m_encryptedWireMode)
		{
			size_t nlPos = m_wireBuffer.find('\n');
			if (nlPos != std::string::npos)
			{
				size_t line1End = nlPos;
				if (line1End > 0 && m_wireBuffer[line1End - 1] == '\r')
				{
					--line1End;
				}
				std::string line1 = m_wireBuffer.substr(0, line1End);

				if (line1.rfind("=ybegin ", 0) == 0 || line1.rfind("begin ", 0) == 0)
				{
					m_encryptedWireMode = false;
				}
				else
				{
					std::vector<uint8_t> ptLine1;
					std::vector<uint8_t> salt1;
					auto st = m_decryptor->DecryptControlLine(
						reinterpret_cast<const uint8_t*>(line1.data()),
						line1.size(),
						m_segmentIndex,
						1,
						true,
						ptLine1,
						&salt1
					);
					if (st == YEncDecryptor::Status::Ok && ptLine1.size() >= 8 && memcmp(ptLine1.data(), "=ybegin ", 8) == 0)
					{
						m_encryptedWireMode = true;
						m_format = efYenc;
					}
					else
					{
						m_encryptedWireMode = false;
					}
				}

				if (!m_encryptedWireMode)
				{
					m_lineBuf.Append(m_wireBuffer.data(), static_cast<int>(m_wireBuffer.size()));
					m_wireBuffer.clear();
					alreadyBuffered = true;
				}
			}
			else if (m_wireBuffer.size() > 8192)
			{
				// T-08-06: bound line 1 staging to 8KB
				m_encryptedWireMode = false;
				m_lineBuf.Append(m_wireBuffer.data(), static_cast<int>(m_wireBuffer.size()));
				m_wireBuffer.clear();
				alreadyBuffered = true;
			}
		}

		if (m_encryptedWireMode)
		{
			bool complete = false;
			if (m_wireBuffer.find("\r\n.\r\n") != std::string::npos ||
				m_wireBuffer.find("\n.\n") != std::string::npos ||
				m_wireBuffer.find("\n.\r\n") != std::string::npos)
			{
				complete = true;
			}
			else if (m_wireBuffer.size() == 3 && m_wireBuffer == ".\r\n")
			{
				complete = true;
			}
			else if (m_wireBuffer.size() == 2 && m_wireBuffer == ".\n")
			{
				complete = true;
			}
			else if (m_wireBuffer.size() >= 5 && m_wireBuffer.substr(m_wireBuffer.size() - 5) == "\r\n.\r\n")
			{
				complete = true;
			}
			else if (m_wireBuffer.size() >= 3 && m_wireBuffer.substr(m_wireBuffer.size() - 3) == "\n.\n")
			{
				complete = true;
			}
			else if (m_wireBuffer.size() >= 4 && m_wireBuffer.substr(m_wireBuffer.size() - 4) == "\n.\r\n")
			{
				complete = true;
			}

			if (complete)
			{
				ProcessRestoredBlock(m_wireBuffer);
				m_wireProcessed = true;
				m_eof = true;
			}

			return 0;
		}
	}

	int outlen = 0;

	if (m_body && m_format == efYenc)
	{
		if ((len >= 13 && !strncmp(buffer, "=yencryption ", 13)) ||
			(len >= 7 && !strncmp(buffer, "=ypart ", 7)))
		{
			m_body = false;
			m_lineBuf.Append(buffer, len);
		}
		else
		{
			outlen = DecodeYenc(buffer, buffer, len);
			if (m_body)
			{
				return outlen;
			}
		}
	}
	else
	{
		if (!alreadyBuffered)
		{
			m_lineBuf.Append(buffer, len);
		}
	}

	char* line = (char*)m_lineBuf;
	while (char* end = strchr(line, '\n'))
	{
		int llen = (int)(end - line + 1);

		if (line[0] == '.' && line[1] == '\r')
		{
			m_eof = true;
			m_lineBuf.SetLength(0);
			return outlen;
		}

		if (m_format == efUnknown)
		{
			m_format = DetectFormat(line, llen);
		}

		if (m_format == efYenc)
		{
			ProcessYenc(line, llen);
			if (m_body)
			{
				const char* next = end + 1;
				int rem = m_lineBuf.Length() - (int)(next - m_lineBuf);
				if (rem >= 13 && !strncmp(next, "=yencryption ", 13))
				{
					m_body = false;
					line = end + 1;
					continue;
				}
				if (rem >= 7 && !strncmp(next, "=ypart ", 7))
				{
					m_body = false;
					line = end + 1;
					continue;
				}
				outlen = DecodeYenc(end + 1, buffer, rem);
				if (m_body)
				{
					m_lineBuf.SetLength(0);
					return outlen;
				}
				line = (char*)m_lineBuf;
				continue;
			}
		}
		else if (m_format == efUx)
		{
			outlen += DecodeUx(line, llen, buffer + outlen);
		}

		line = end + 1;
	}

	if (*line)
	{
		len = m_lineBuf.Length() - (int)(line - m_lineBuf);
		memmove((char*)m_lineBuf, line, len);
		m_lineBuf.SetLength(len);
	}
	else
	{
		m_lineBuf.SetLength(0);
	}

	return outlen;
}

void Decoder::ParseYpart(const char* buffer)
{
	m_part = true;
	m_body = true;
	const char* pb = strstr(buffer, " begin=");
	if (pb)
	{
		pb += 7; //=strlen(" begin=")
		m_beginPos = static_cast<int64>(atoll(pb));
	}
	pb = strstr(buffer, " end=");
	if (pb)
	{
		pb += 5; //=strlen(" end=")
		m_endPos = static_cast<int64>(atoll(pb));
	}
}

void Decoder::ParseName(const char* buffer, const char* bufferEnd)
{
	const char* pb = buffer;
	pb += 6; //=strlen(" name=")
	const char* pe = pb;
	while (pe < bufferEnd && *pe != '\0' && *pe != '\n' && *pe != '\r')
	{
		if (pe + 7 <= bufferEnd && strncmp(pe, "=ypart ", 7) == 0)
		{
			ParseYpart(pe);
			break;
		}
		++pe;
	}

	m_articleFilename = WebUtil::Latin1ToUtf8(CString(pb, (int)(pe - pb)));
}

Decoder::EFormat Decoder::DetectFormat(const char* buffer, int len)
{
	if (!strncmp(buffer, "=ybegin ", 8))
	{
		return efYenc;
	}

	if ((len == 62 || len == 63) && (buffer[62] == '\n' || buffer[62] == '\r') && *buffer == 'M')
	{
		return efUx;
	}

	if (!strncmp(buffer, "begin ", 6))
	{
		bool ok = true;
		buffer += 6; //strlen("begin ")
		while (*buffer && *buffer != ' ')
		{
			char ch = *buffer++;
			if (ch < '0' || ch > '7')
			{
				ok = false;
				break;
			}
		}
		if (ok)
		{
			return efUx;
		}
	}

	return efUnknown;
}

void Decoder::ProcessYenc(char* buffer, int len)
{
	// 1. Check =ybegin (Prefix length 8)
	if (len >= 8 && !strncmp(buffer, "=ybegin ", 8))
	{
		m_begin = true;
		char* pb = strstr(buffer, " size=");
		if (pb && pb + 6 < buffer + len) // Ensure room for " size="
		{
			pb += 6;
			m_size = static_cast<int64>(atoll(pb));
		}
		
		char* partPtr = strstr(buffer, " part=");
		// Ensure marker is within the current buffer's length
		if (partPtr && partPtr >= buffer + len) partPtr = nullptr;
		m_part = partPtr != nullptr;

		if (!m_part)
		{
			m_body = true;
			m_beginPos = 1;
			m_endPos = m_size;
		}

		pb = strstr(buffer, " name=");
		if (pb && pb + 6 < buffer + len) // Ensure room for " name="
		{
			ParseName(pb, buffer + len);
		}
	}
	// 2. Check =ypart (Prefix length 7)
	else if (len >= 7 && !strncmp(buffer, "=ypart ", 7))
	{
		ParseYpart(buffer);
	}
	// 3. Check =yend (Prefix length 6)
	else if (len >= 6 && !strncmp(buffer, "=yend ", 6))
	{
		m_end = true;
		int crcOffset = 7 + static_cast<int>(m_part); // " crc32=" (7) or " pcrc32=" (8)
		char* pb = strstr(buffer, m_part ? " pcrc32=" : " crc32=");

		if (pb && pb + crcOffset < buffer + len)
		{
			m_crc = true;
			pb += crcOffset;
			m_expectedCRC = static_cast<uint32>(strtoul(pb, nullptr, 16));
		}
		
		pb = strstr(buffer, " size=");
		if (pb && pb + 6 < buffer + len)
		{
			pb += 6;
			m_endSize = atoll(pb);
		}
	}
	// 4. Check =yencryption (Prefix length 13)
	else if (len >= 13 && !strncmp(buffer, "=yencryption ", 13))
	{
		ParseEncryption(buffer, len);
	}
}

void Decoder::ParseEncryption(const char* buffer, int len)
{
	m_encrypted = true;
	if (!YEncDecryptor::ParseYEncryption(buffer, len, m_cipher, m_salt, m_tag))
	{
		m_authFailed = true;
	}
	m_body = true;
}

int Decoder::DecodeYenc(char* buffer, char* outbuf, int len)
{
	const void* src = buffer;
	void* dst = outbuf;

	auto endseq = rapidyenc_decode_incremental(&src, &dst, len, (RapidYencDecoderState*)&m_state);

	int bytesWritten = static_cast<int>(static_cast<char*>(dst) - outbuf);

	// endseq:
	//   0: no end sequence found
	//   1: \r\n=y sequence found, src points to byte after 'y'
	//   2: \r\n.\r\n sequence found, src points to byte after last '\n'
	if (endseq != 0) 
	{
		// switch back to line mode to process '=yend'- or eof- marker
		m_lineBuf.SetLength(0);
		m_lineBuf.Append(endseq == 1 ? "=y" : ".\r\n");
		int bytesConsumed = static_cast<int>(static_cast<const char*>(src) - buffer);
		int rem = len - bytesConsumed;
		if (rem > 0)
		{
			m_lineBuf.Append((const char*)src, rem);
		}
		m_body = false;
	}

	if (m_crcCheck)
	{
		m_crc32.Append(reinterpret_cast<unsigned char*>(outbuf), bytesWritten);
	}

	m_outSize += bytesWritten;

	if (m_encrypted)
	{
		m_cipherPayload.insert(m_cipherPayload.end(),
			reinterpret_cast<const uint8_t*>(outbuf),
			reinterpret_cast<const uint8_t*>(outbuf) + bytesWritten);
	}

	return bytesWritten;
}

void Decoder::ProcessRestoredBlock(const std::string& wireBlock)
{
	if (!m_decryptor)
	{
		m_authFailed = true;
		return;
	}

	std::string cleanBlock;
	std::vector<uint8_t> line1Salt;
	YEncDecryptor::YEncryptionHeader header;
	bool ok = m_decryptor->RestoreControlLines(
		wireBlock.data(), wireBlock.size(), m_segmentIndex, cleanBlock, line1Salt, &header
	);
	if (!ok)
	{
		m_authFailed = true;
		m_decryptedPlaintext.clear();
		return;
	}

	m_encrypted = true;
	m_cipher = header.cipher;
	memcpy(m_salt, header.salt.data(), 16);
	memcpy(m_tag, header.tag.data(), 16);

	// Reset state, then run the restored article through the ordinary decoder.
	// This keeps control-line restoration separate without duplicating the
	// line/body transition logic (especially the buffered =yend transition).
	m_format = efUnknown;
	m_begin = false;
	m_part = false;
	m_body = false;
	m_end = false;
	m_crc = false;
	m_eof = false;
	m_state = 0;
	m_expectedCRC = 0;
	m_crc32.Reset();
	m_outSize = 0;
	m_cipherPayload.clear();
	m_lineBuf.SetLength(0);
	m_wireProcessed = true;

	DecodeBuffer(cleanBlock.data(), static_cast<int>(cleanBlock.size()));
}

Decoder::EStatus Decoder::Check()
{
	if (m_encryptedWireMode && !m_wireProcessed)
	{
		m_eof = true;
		ProcessRestoredBlock(m_wireBuffer);
		m_wireProcessed = true;
	}

	if (m_authFailed)
	{
		return dsAuthFailed;
	}

	switch (m_format)
	{
		case efYenc:
			return CheckYenc();
			 
		case efUx:
			return CheckUx();

		default:
			return dsUnknownError;
	}
}

Decoder::EStatus Decoder::CheckYenc()
{
	m_calculatedCRC = m_crc32.Finish();

	debug("Expected crc32=%x", m_expectedCRC);
	debug("Calculated crc32=%x", m_calculatedCRC);

	if (!m_begin)
	{
		return dsNoBinaryData;
	}
	else if (!m_end)
	{
		return dsArticleIncomplete;
	}
	else if (m_authFailed)
	{
		return dsAuthFailed;
	}
	else if ((!m_part && m_size != m_endSize) || (m_endSize != m_outSize))
	{
		return dsInvalidSize;
	}
	else if (m_crcCheck && m_crc && (m_expectedCRC != m_calculatedCRC))
	{
		return dsCrcError;
	}

	if (m_encrypted)
	{
		if (m_segmentIndex == 0 || !m_decryptor)
		{
			m_authFailed = true;
			m_decryptedPlaintext.clear();
			return dsAuthFailed;
		}

		m_decryptedPlaintext.clear();
		YEncDecryptor::Status st = m_decryptor->AuthenticateAndDecrypt(
			m_cipherPayload.data(), m_cipherPayload.size(),
			m_salt, m_tag, m_segmentIndex, m_decryptedPlaintext
		);
		if (st != YEncDecryptor::Status::Ok)
		{
			m_authFailed = true;
			m_decryptedPlaintext.clear();
			return dsAuthFailed;
		}
	}

	return dsFinished;
}

bool Decoder::AuthenticateAndDecrypt(const uint8_t* ciphertext, size_t cipherLen, std::vector<uint8_t>& outPlaintext)
{
	outPlaintext.clear();
	if (!m_decryptor)
	{
		return false;
	}
	YEncDecryptor::Status st = m_decryptor->AuthenticateAndDecrypt(
		ciphertext, cipherLen, m_salt, m_tag, m_segmentIndex, outPlaintext
	);
	if (st != YEncDecryptor::Status::Ok)
	{
		m_authFailed = true;
		outPlaintext.clear();
		return false;
	}
	return true;
}


/* DecodeUx-function uses portions of code from tool UUDECODE by Clem Dye
 * UUDECODE.c (http://www.bastet.com/uue.zip)
 * Copyright (C) 1998 Clem Dye
 *
 * Released under GPL (thanks)
 */

#define UU_DECODE_CHAR(c) (c == '`' ? 0 : (((c) - ' ') & 077))

int Decoder::DecodeUx(const char* inbuf, int len, char* outbuf)
{
	if (!m_body)
	{
		if (!strncmp(inbuf, "begin ", 6))
		{
			const char* pb = inbuf;
			pb += 6; //strlen("begin ")

			// skip file-permissions
			for (; *pb != ' ' && *pb != '\0' && *pb != '\n' && *pb != '\r'; pb++) ;
			pb++;

			// extracting filename
			const char* pe;
			for (pe = pb; *pe != '\0' && *pe != '\n' && *pe != '\r'; pe++) ;
			m_articleFilename = WebUtil::Latin1ToUtf8(CString(pb, static_cast<int>(pe - pb)));

			m_body = true;
			return 0;
		}
		else if ((len == 62 || len == 63) && (inbuf[62] == '\n' || inbuf[62] == '\r') && *inbuf == 'M')
		{
			m_body = true;
		}
	}

	if (m_body && (!strncmp(inbuf, "end ", 4) || *inbuf == '`'))
	{
		m_end = true;
	}

	if (m_body && !m_end)
	{
		int effLen = UU_DECODE_CHAR(inbuf[0]);
		if (effLen > len)
		{
			// error;
			return 0;
		}

		const char* iptr = inbuf;
		char* optr = outbuf;
		for (++iptr; effLen > 0; iptr += 4, effLen -= 3)
		{
			if (effLen >= 3)
			{
				*optr++ = UU_DECODE_CHAR (iptr[0]) << 2 | UU_DECODE_CHAR (iptr[1]) >> 4;
				*optr++ = UU_DECODE_CHAR (iptr[1]) << 4 | UU_DECODE_CHAR (iptr[2]) >> 2;
				*optr++ = UU_DECODE_CHAR (iptr[2]) << 6 | UU_DECODE_CHAR (iptr[3]);
			}
			else
			{
				*optr++ = UU_DECODE_CHAR (iptr[0]) << 2 | UU_DECODE_CHAR (iptr[1]) >> 4;
				if (effLen >= 2)
				{
					*optr++ = UU_DECODE_CHAR (iptr[1]) << 4 | UU_DECODE_CHAR (iptr[2]) >> 2;
				}
			}
		}

		return static_cast<int>(optr - outbuf);
	}

	return 0;
}

Decoder::EStatus Decoder::CheckUx()
{
	if (!m_body)
	{
		return dsNoBinaryData;
	}

	return dsFinished;
}

void Decoder::ProcessRaw(char* buffer, int len)
{
	switch (m_state)
	{
		case 1:
			m_eof = len >= 4 && buffer[0] == '\n' &&
				buffer[1] == '.' && buffer[2] == '\r' && buffer[3] == '\n';
			break;

		case 2:
			m_eof = len >= 3 && buffer[0] == '.' && buffer[1] == '\r' && buffer[2] == '\n';
			break;

		case 3:
			m_eof = len >= 2 && buffer[0] == '\r' && buffer[1] == '\n';
			break;

		case 4:
			m_eof = len >= 1 && buffer[0] == '\n';
			break;
	}

	m_eof |= std::string_view(buffer, len).find("\r\n.\r\n") != std::string_view::npos;

	if (len >= 4 && buffer[len-4] == '\r' && buffer[len-3] == '\n' &&
		buffer[len-2] == '.' && buffer[len-1] == '\r')
	{
		m_state = 4;
	}
	else if (len >= 3 && buffer[len-3] == '\r' && buffer[len-2] == '\n' && buffer[len-1] == '.')
	{
		m_state = 3;
	}
	else if (len >= 2 && buffer[len-2] == '\r' && buffer[len-1] == '\n')
	{
		m_state = 2;
	}
	else if (len >= 1 && buffer[len-1] == '\r')
	{
		m_state = 1;
	}
	else
	{
		m_state = 0;
	}
}
