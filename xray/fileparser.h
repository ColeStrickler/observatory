#pragma once
#include <Windows.h>
#include <wincrypt.h>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>
#include "raii.h"
#include "const.h"
#include "helper.h"


BYTE* getFileBase(const char* filePath, DWORD* _Out_ fileSize);


namespace staticparse
{

	typedef struct Hash_Info
	{
		std::string MD5;
		std::string SHA1;
		std::string SHA256;
	};

	typedef struct parsed_PeHeader32
	{
		IMAGE_DOS_HEADER DosHeader;
		IMAGE_NT_HEADERS32 NtHeaders32;
		std::vector<std::string> Imports;
		std::vector<std::string> Exports;
		std::vector<IMAGE_SECTION_HEADER> Sections;
		std::vector<DWORD> Errors;
	};

	typedef struct parsed_PeHeader64
	{
		IMAGE_DOS_HEADER DosHeader;
		IMAGE_NT_HEADERS64 NtHeaders64;
	
		std::vector<std::string> Imports;
		std::vector<std::string> Exports;
		std::vector<IMAGE_SECTION_HEADER> Sections;
		
	};


	

	typedef struct Section
	{
		std::string SectionName;
		DWORD SizeOfRawData;
		Hash_Info HashInfo;
	};


	typedef struct ExtractInfo
	{
		std::string												FileName;
		DWORD													FileSize;
		BOOL													x86;
		Hash_Info												HashInfo;
		std::map<std::string, std::vector<std::string>>			Imports;
		std::vector<std::string>								Exports;
		std::vector<std::string>								Resources;
		std::vector<Section>									Sections;
		std::vector<std::string>								Strings;
		std::vector<DWORD>										Errors;
	};


	class Pe_Parser
	{
		
	public:
		Pe_Parser(std::string FilePath);
		parsed_PeHeader32* Parse32();
		parsed_PeHeader64* Parse64();
		ExtractInfo Parse(); 
		

	public:
		ExtractInfo ParsedInfo;


	private:
		void GetBasicFileInfo();
		void ParseImports();
		void ParseExports();
		void GetHashes(void* buf, DWORD size, Hash_Info* hash_struct);
		void ParseSections();
		void ParseStrings();

	private:
		BYTE* Base;
		std::string Path;
		

	};

	

}


