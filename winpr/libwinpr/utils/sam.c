/**
 * WinPR: Windows Portable Runtime
 * Security Accounts Manager (SAM)
 *
 * Copyright 2012 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <winpr/config.h>
#include <winpr/path.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <winpr/wtypes.h>
#include <winpr/crt.h>
#include <winpr/sam.h>
#include <winpr/cast.h>
#include <winpr/print.h>
#include <winpr/file.h>

#include "../log.h"
#include "../utils.h"

#ifdef WINPR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#define TAG WINPR_TAG("utils")

struct winpr_sam
{
	FILE* fp;
	char* line;
	char* buffer;
	char* context;
	size_t bufferSize;
	BOOL readOnly;
};

static BOOL SamIsHexString(const char* value, size_t length)
{
	if (!value)
		return FALSE;

	for (size_t x = 0; x < length; x++)
	{
		const char ch = value[x];
		if (!(((ch >= '0') && (ch <= '9')) || ((ch >= 'a') && (ch <= 'f')) ||
		      ((ch >= 'A') && (ch <= 'F'))))
			return FALSE;
	}

	return TRUE;
}

static WINPR_SAM_ENTRY* SamEntryFromDataA(LPCSTR User, DWORD UserLength, LPCSTR Domain,
                                          DWORD DomainLength)
{
	WINPR_SAM_ENTRY* entry = calloc(1, sizeof(WINPR_SAM_ENTRY));
	if (!entry)
		return nullptr;
	if (User && (UserLength > 0))
		entry->User = _strdup(User);
	entry->UserLength = UserLength;
	if (Domain && (DomainLength > 0))
		entry->Domain = _strdup(Domain);
	entry->DomainLength = DomainLength;
	return entry;
}

static BOOL SamAreEntriesEqual(const WINPR_SAM_ENTRY* a, const WINPR_SAM_ENTRY* b)
{
	if (!a || !b)
		return FALSE;
	if (a->UserLength != b->UserLength)
		return FALSE;
	if (a->DomainLength != b->DomainLength)
		return FALSE;
	if (a->UserLength > 0)
	{
		if (!a->User || !b->User)
			return FALSE;
		if (strncmp(a->User, b->User, a->UserLength) != 0)
			return FALSE;
	}
	if (a->DomainLength > 0)
	{
		if (!a->Domain || !b->Domain)
			return FALSE;
		if (strncmp(a->Domain, b->Domain, a->DomainLength) != 0)
			return FALSE;
	}
	return TRUE;
}

WINPR_SAM* SamOpen(const char* filename, BOOL readOnly)
{
	FILE* fp = nullptr;
	WINPR_SAM* sam = nullptr;
	char* allocatedFileName = nullptr;

	if (!filename)
	{
		allocatedFileName = winpr_GetConfigFilePath(TRUE, "SAM");
		filename = allocatedFileName;
	}

	if (readOnly)
		fp = winpr_fopen(filename, "r");
	else
	{
		fp = winpr_fopen(filename, "r+");

		if (!fp)
			fp = winpr_fopen(filename, "w+");
	}
	free(allocatedFileName);
	/* Keep password-equivalent SAM data out of stdio-owned buffers. */
	if (fp && (setvbuf(fp, nullptr, _IONBF, 0) != 0))
	{
		(void)fclose(fp);
		fp = nullptr;
	}

	if (fp)
	{
		sam = (WINPR_SAM*)calloc(1, sizeof(WINPR_SAM));

		if (!sam)
		{
			(void)fclose(fp);
			return nullptr;
		}

		sam->readOnly = readOnly;
		sam->fp = fp;
	}
	else
	{
		WLog_DBG(TAG, "Could not open SAM file!");
		return nullptr;
	}

	return sam;
}

static BOOL SamLookupStart(WINPR_SAM* sam)
{
	size_t readSize = 0;
	INT64 fileSize = 0;

	if (!sam || !sam->fp)
		return FALSE;

	if (_fseeki64(sam->fp, 0, SEEK_END) != 0)
		return FALSE;
	fileSize = _ftelli64(sam->fp);
	if (_fseeki64(sam->fp, 0, SEEK_SET) != 0)
		return FALSE;

	if (fileSize < 1)
		return FALSE;

	sam->context = nullptr;
	if ((UINT64)fileSize > (SIZE_MAX - 2))
		return FALSE;
	sam->bufferSize = (size_t)fileSize + 2;
	sam->buffer = (char*)calloc(sam->bufferSize, 1);

	if (!sam->buffer)
		return FALSE;

	readSize = fread(sam->buffer, (size_t)fileSize, 1, sam->fp);

	if (!readSize)
	{
		if (!ferror(sam->fp))
			readSize = (size_t)fileSize;
	}

	if (readSize < 1)
	{
		SecureZeroMemory(sam->buffer, sam->bufferSize);
		free(sam->buffer);
		sam->buffer = nullptr;
		sam->bufferSize = 0;
		return FALSE;
	}

	sam->buffer[fileSize] = '\n';
	sam->buffer[fileSize + 1] = '\0';
	sam->line = strtok_s(sam->buffer, "\n", &sam->context);
	return TRUE;
}

static void SamLookupFinish(WINPR_SAM* sam)
{
	if (!sam)
		return;
	if (sam->buffer)
		SecureZeroMemory(sam->buffer, sam->bufferSize);
	free(sam->buffer);
	sam->buffer = nullptr;
	sam->line = nullptr;
	sam->context = nullptr;
	sam->bufferSize = 0;
}

static BOOL SamReadEntry(WINPR_SAM* sam, WINPR_SAM_ENTRY* entry)
{
	char* p[5] = WINPR_C_ARRAY_INIT;
	size_t count = 0;

	if (!sam || !entry || !sam->line)
		return FALSE;

	char* cur = sam->line;

	while ((cur = strchr(cur, ':')) != nullptr)
	{
		count++;
		cur++;
	}

	if (count < 4)
		return FALSE;

	p[0] = sam->line;
	p[1] = strchr(p[0], ':') + 1;
	p[2] = strchr(p[1], ':') + 1;
	p[3] = strchr(p[2], ':') + 1;
	p[4] = strchr(p[3], ':') + 1;
	const size_t UserLength = WINPR_ASSERTING_INT_CAST(size_t, (p[1] - p[0] - 1));
	const size_t DomainLength = WINPR_ASSERTING_INT_CAST(size_t, (p[2] - p[1] - 1));
	const size_t LmHashLength = WINPR_ASSERTING_INT_CAST(size_t, (p[3] - p[2] - 1));
	const size_t NtHashLength = WINPR_ASSERTING_INT_CAST(size_t, (p[4] - p[3] - 1));
	if ((UserLength > UINT32_MAX) || (UserLength > (SIZE_MAX - 1)) || (DomainLength > UINT32_MAX) ||
	    (DomainLength > (SIZE_MAX - 1)))
		return FALSE;

	if ((LmHashLength != 0) && (LmHashLength != 32))
		return FALSE;

	if ((NtHashLength != 0) && (NtHashLength != 32))
		return FALSE;

	entry->UserLength = (UINT32)UserLength;
	entry->User = (LPSTR)malloc(UserLength + 1);

	if (!entry->User)
		return FALSE;

	entry->User[entry->UserLength] = '\0';
	entry->DomainLength = (UINT32)DomainLength;
	memcpy(entry->User, p[0], entry->UserLength);

	if (entry->DomainLength > 0)
	{
		entry->Domain = (LPSTR)malloc(DomainLength + 1);

		if (!entry->Domain)
		{
			free(entry->User);
			entry->User = nullptr;
			return FALSE;
		}

		memcpy(entry->Domain, p[1], entry->DomainLength);
		entry->Domain[entry->DomainLength] = '\0';
	}
	else
		entry->Domain = nullptr;

	if (LmHashLength == 32)
	{
		if (!SamIsHexString(p[2], LmHashLength))
			return FALSE;
		const size_t rc =
		    winpr_HexStringToBinBuffer(p[2], LmHashLength, entry->LmHash, sizeof(entry->LmHash));
		if (rc != 16)
			return FALSE;
	}

	if (NtHashLength == 32)
	{
		if (!SamIsHexString(p[3], NtHashLength))
			return FALSE;
		const size_t rc = winpr_HexStringToBinBuffer(p[3], NtHashLength, (BYTE*)entry->NtHash,
		                                             sizeof(entry->NtHash));
		if (rc != 16)
			return FALSE;
	}

	return TRUE;
}

void SamFreeEntry(WINPR_ATTR_UNUSED WINPR_SAM* sam, WINPR_SAM_ENTRY* entry)
{
	SamResetEntry(entry);
	if (entry)
		SecureZeroMemory(entry, sizeof(*entry));
	free(entry);
}

void SamResetEntry(WINPR_SAM_ENTRY* entry)
{
	if (!entry)
		return;

	free(entry->User);
	free(entry->Domain);
	entry->User = nullptr;
	entry->UserLength = 0;
	entry->Domain = nullptr;
	entry->DomainLength = 0;
	SecureZeroMemory(entry->LmHash, sizeof(entry->LmHash));
	SecureZeroMemory(entry->NtHash, sizeof(entry->NtHash));
}

WINPR_SAM_ENTRY* SamLookupUserA(WINPR_SAM* sam, LPCSTR User, UINT32 UserLength, LPCSTR Domain,
                                UINT32 DomainLength)
{
	size_t length = 0;
	BOOL found = FALSE;
	WINPR_SAM_ENTRY* search = SamEntryFromDataA(User, UserLength, Domain, DomainLength);
	WINPR_SAM_ENTRY* entry = (WINPR_SAM_ENTRY*)calloc(1, sizeof(WINPR_SAM_ENTRY));

	if (!entry || !search)
		goto fail;

	if (!SamLookupStart(sam))
		goto fail;

	while (sam->line != nullptr)
	{
		length = strlen(sam->line);

		if (length > 1)
		{
			if (sam->line[0] != '#')
			{
				if (!SamReadEntry(sam, entry))
				{
					goto out_fail;
				}

				if (SamAreEntriesEqual(entry, search))
				{
					found = 1;
					break;
				}
			}
		}

		SamResetEntry(entry);
		sam->line = strtok_s(nullptr, "\n", &sam->context);
	}

out_fail:
	SamLookupFinish(sam);
fail:
	SamFreeEntry(sam, search);

	if (!found)
	{
		SamFreeEntry(sam, entry);
		return nullptr;
	}

	return entry;
}

WINPR_SAM_ENTRY* SamLookupUserW(WINPR_SAM* sam, LPCWSTR User, UINT32 UserLength, LPCWSTR Domain,
                                UINT32 DomainLength)
{
	WINPR_SAM_ENTRY* entry = nullptr;
	char* utfUser = nullptr;
	char* utfDomain = nullptr;
	size_t userCharLen = 0;
	size_t domainCharLen = 0;

	utfUser = ConvertWCharNToUtf8Alloc(User, UserLength / sizeof(WCHAR), &userCharLen);
	if (!utfUser)
		goto fail;
	if (DomainLength > 0)
	{
		utfDomain = ConvertWCharNToUtf8Alloc(Domain, DomainLength / sizeof(WCHAR), &domainCharLen);
		if (!utfDomain)
			goto fail;
	}
	entry = SamLookupUserA(sam, utfUser, (UINT32)userCharLen, utfDomain, (UINT32)domainCharLen);
	if (entry)
	{
		free(entry->User);
		free(entry->Domain);
		entry->User = nullptr;
		entry->Domain = nullptr;
		if (User)
			entry->User = (char*)winpr_wcsndup(User, UserLength / sizeof(WCHAR));
		entry->UserLength = UserLength;
		if (Domain)
			entry->Domain = (char*)winpr_wcsndup(Domain, DomainLength / sizeof(WCHAR));
		entry->DomainLength = DomainLength;
	}
fail:
	free(utfUser);
	free(utfDomain);
	return entry;
}

void SamClose(WINPR_SAM* sam)
{
	if (sam != nullptr)
	{
		SamLookupFinish(sam);
		if (sam->fp)
			(void)fclose(sam->fp);
		SecureZeroMemory(sam, sizeof(*sam));
		free(sam);
	}
}
