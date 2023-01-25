#include "fileparser.h"


BYTE* getFileBase(const char* filePath, DWORD* _Out_ fileSize) {

	LPVOID fileData;
	HANDLE fileHandle = CreateFileA(filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, NULL, NULL);
	*fileSize = GetFileSize(fileHandle, NULL);
	fileData = new BYTE[*fileSize];
	ReadFile(fileHandle, fileData, *fileSize, NULL, NULL);
	CloseHandle(fileHandle);
	return (BYTE*)fileData;
}


DWORD Rva2Offset(DWORD Rva, PIMAGE_SECTION_HEADER pSectionCopy, PIMAGE_NT_HEADERS64 pNtHeaders)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSectionHeader;
	if (Rva == 0)
	{
		return (Rva);
	}
	pSectionHeader = pSectionCopy;
	for (i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (Rva >= pSectionHeader->VirtualAddress && Rva < pSectionHeader->VirtualAddress +
			pSectionHeader->Misc.VirtualSize)
		{
			break;
		}
		pSectionHeader++;
	}
	return (Rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData);
}


DWORD Rva2Offset32(DWORD Rva, PIMAGE_SECTION_HEADER pSectionCopy, PIMAGE_NT_HEADERS32 pNtHeaders)
{
	size_t i = 0;
	PIMAGE_SECTION_HEADER pSectionHeader;
	if (Rva == 0)
	{
		return (Rva);
	}
	pSectionHeader = pSectionCopy;
	for (i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (Rva >= pSectionHeader->VirtualAddress && Rva < pSectionHeader->VirtualAddress +
			pSectionHeader->Misc.VirtualSize)
		{
			break;
		}
		pSectionHeader++;
	}
	return (Rva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData);
}




staticparse::Pe_Parser::Pe_Parser(std::string FilePath) : Path(FilePath)
{
	Base = getFileBase(Path.c_str(), &ParsedInfo.FileSize);

}


staticparse::parsed_PeHeader32* staticparse::Pe_Parser::Parse32()
{
	return nullptr;
}



void staticparse::Pe_Parser::GetHashes(void* buf, DWORD size, Hash_Info* hash_struct)
{

	const char* hex = "0123456789abcdef";
	HCRYPTPROV hProv = NULL;
	HCRYPTPROV md5 = NULL;
	HCRYPTPROV sha1 = NULL;
	HCRYPTPROV sha256 = NULL;
	BOOL success_md5 = TRUE;
	BOOL success_sha1 = TRUE;
	BOOL success_sha256 = TRUE;
	std::vector<HCRYPTPROV> hash_providers;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		ParsedInfo.Errors.push_back(ERROR_WINCRYPT_CONTEXT);
		return;
	}

	success_md5 = CryptCreateHash(hProv, CALG_MD5, 0, 0, &md5);
	success_sha1 = CryptCreateHash(hProv, CALG_SHA1, 0, 0, &sha1);
	success_sha256 = CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &sha256);
	
	hash_providers = { md5, sha1, sha256 };

	if (!success_md5 || !success_sha1 || !success_sha256)
	{
		ParsedInfo.Errors.push_back(ERROR_WINCRYPT_HASH);
		CryptReleaseContext(hProv, 0);
		return;
	}

	int switchInt = 0;


	for (auto& hp : hash_providers)
	{
		// PERFORM HASH
		if (!CryptHashData(hp, (BYTE*)buf, size, 0))
		{
			ParsedInfo.Errors.push_back(ERROR_WINCRYPT_HASH);
			break;
		}

		// GET SIZE OF HASH
		DWORD hashSize = 0;
		DWORD dwSize = sizeof(DWORD);
		if (!CryptGetHashParam(hp, HP_HASHSIZE, (BYTE*)&hashSize, &dwSize, 0))
		{
			ParsedInfo.Errors.push_back(ERROR_WINCRYPT_HASH);
			break;
		}

		BYTE* hash_buf = RAII::NewBuffer(hashSize).Get();
		if (!CryptGetHashParam(hp, HP_HASHVAL, hash_buf, &hashSize, 0))
		{
			ParsedInfo.Errors.push_back(ERROR_WINCRYPT_HASH);
			break;
		}

		RAII::NewBuffer buffer(0x500);

		BYTE* buf = buffer.Get();

		for (int i = 0; i < hashSize; i++) {
			buf[i * 2] = hex[hash_buf[i] >> 4];
			buf[(i * 2) + 1] = hex[hash_buf[i] & 0xF];
		}

		std::string hashVal((char*)buf);
		
		if (switchInt == 0)
		{
			hash_struct->MD5 = hashVal;
		}
		else if (switchInt == 1)
		{
			hash_struct->SHA1 = hashVal;
		}
		else 
		{
			hash_struct->SHA256 = hashVal;
		}
		switchInt++;


	}


	CryptDestroyHash(sha256);
	CryptDestroyHash(sha1);
	CryptDestroyHash(md5);
	CryptReleaseContext(hProv, 0);
	return;


}


void staticparse::Pe_Parser::GetBasicFileInfo()
{
	GetHashes(Base, ParsedInfo.FileSize, &ParsedInfo.HashInfo);

	int lastSlash = 0;
	for (int i = Path.size() - 1; i >= 0; i--)
	{
		if (Path[i] == '\\')
		{
			lastSlash = i;
			break;
		}

	}
	ParsedInfo.FileName = std::string(Path.c_str() + lastSlash + 1);
}


void staticparse::Pe_Parser::ParseSections()
{
	auto dos = (PIMAGE_DOS_HEADER)Base;
	auto file = (PIMAGE_FILE_HEADER)(Base + dos->e_lfanew + sizeof(IMAGE_NT_SIGNATURE));




	// 64bit
	if (file->Machine == IMAGE_FILE_MACHINE_AMD64 || file->Machine == IMAGE_FILE_MACHINE_IA64)
	{
		ParsedInfo.x86 = FALSE;
		auto nt = (PIMAGE_NT_HEADERS64)(Base + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
		{
			ParsedInfo.Errors.push_back(ERROR_NT_SIGNATURE);
			return;
		}

		int numSections = nt->FileHeader.NumberOfSections;

		auto sectionAddr = ((uintptr_t)&nt->OptionalHeader + (uintptr_t)nt->FileHeader.SizeOfOptionalHeader);
		for (int i = 0; i < numSections; i++) {
			auto section = (PIMAGE_SECTION_HEADER)sectionAddr;
			Section newSection;
			newSection.SectionName = std::string((char*)section->Name);
			newSection.SizeOfRawData = section->SizeOfRawData;
			GetHashes(Base + section->PointerToRawData, section->SizeOfRawData, &newSection.HashInfo);
			ParsedInfo.Sections.push_back(newSection);
			sectionAddr = sectionAddr + sizeof(IMAGE_SECTION_HEADER);
		}


	}
	else
	{
		ParsedInfo.x86 = TRUE;
		auto nt = (PIMAGE_NT_HEADERS32)(Base + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
		{
			ParsedInfo.Errors.push_back(ERROR_NT_SIGNATURE);
			return;
		}

		int numSections = nt->FileHeader.NumberOfSections;

		auto sectionAddr = ((uintptr_t)&nt->OptionalHeader + (uintptr_t)nt->FileHeader.SizeOfOptionalHeader);
		for (int i = 0; i < numSections; i++) {
			auto section = (PIMAGE_SECTION_HEADER)sectionAddr;
			Section newSection;
			newSection.SectionName = std::string((char*)section->Name);
			newSection.SizeOfRawData = section->SizeOfRawData;
			GetHashes(Base + section->PointerToRawData, section->SizeOfRawData, &newSection.HashInfo);
			ParsedInfo.Sections.push_back(newSection);
			sectionAddr = sectionAddr + sizeof(IMAGE_SECTION_HEADER);
		}
	}


}



void staticparse::Pe_Parser::ParseImports()
{
	auto dos = (PIMAGE_DOS_HEADER)Base;
	PIMAGE_IMPORT_DESCRIPTOR iDescriptor = nullptr;
	



	if (!ParsedInfo.x86)								// 64bit
	{
		
		auto nt = (PIMAGE_NT_HEADERS64)(Base + dos->e_lfanew);
		auto pSectionHeader = IMAGE_FIRST_SECTION(nt);
		int numSections = nt->FileHeader.NumberOfSections;
		if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			iDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(Base + Rva2Offset(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSectionHeader, nt));
			while (iDescriptor->Name != NULL)
			{
				std::string libary(((char*)(Rva2Offset(iDescriptor->Name, pSectionHeader, nt) + Base)));
				auto thunkILT = (PIMAGE_THUNK_DATA64)(Base + Rva2Offset(iDescriptor->OriginalFirstThunk, pSectionHeader, nt));

				while (thunkILT->u1.AddressOfData != 0)
				{
					if (!(thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
					{
						PIMAGE_IMPORT_BY_NAME nameArray = (PIMAGE_IMPORT_BY_NAME)(Rva2Offset(thunkILT->u1.AddressOfData, pSectionHeader, nt));		
						std::string function((char*)(Base + Rva2Offset((DWORD)nameArray->Name, pSectionHeader, nt)));
						ParsedInfo.Imports[libary].push_back(function);
	
					}
					
					thunkILT++;

				}

				iDescriptor++;
			}
		}

	}
	else												// 32bit
	{
		auto nt = (PIMAGE_NT_HEADERS32)(Base + dos->e_lfanew);
		auto pSectionHeader = IMAGE_FIRST_SECTION(nt);
		int numSections = nt->FileHeader.NumberOfSections;
		if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			iDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(Base + Rva2Offset32(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pSectionHeader, nt));
			while (iDescriptor->Name != NULL)
			{

				std::string libary(((char*)(Rva2Offset32(iDescriptor->Name, pSectionHeader, nt) + Base)));
				auto thunkILT = (PIMAGE_THUNK_DATA32)(Base + Rva2Offset32(iDescriptor->OriginalFirstThunk, pSectionHeader, nt));
				while (thunkILT->u1.AddressOfData != 0)
				{
					if (!(thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG32))
					{
						PIMAGE_IMPORT_BY_NAME nameArray = (PIMAGE_IMPORT_BY_NAME)(Rva2Offset32(thunkILT->u1.AddressOfData, pSectionHeader, nt));
					
						std::string function((char*)(Base + Rva2Offset32((DWORD)nameArray->Name, pSectionHeader, nt)));
						ParsedInfo.Imports[libary].push_back(function);
		
					}

					thunkILT++;

				}

				iDescriptor++;
			}
		}
	}

	return;
}


staticparse::ExtractInfo staticparse::Pe_Parser::Parse()
{
	GetBasicFileInfo();
	ParseSections();
	for (auto& err : ParsedInfo.Errors)
	{
		if (err == ERROR_DOS_SIGNATURE || err == ERROR_NT_SIGNATURE)
		{
			return ParsedInfo;
		}
	}
	ParseImports();

	

	return ParsedInfo;
}
