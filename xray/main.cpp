#include <Windows.h>

#include <stdlib.h>
#include <iostream>

#include "raii.h"
#include "fileparser.h"
#include "zipClass.h"
#include "manager.h"


using namespace nlohmann;

void test_pe_parser()
{
	//staticparse::Pe_Parser parse("C:\\Users\\Cole\\Documents\\C++\\HookFinder\\x64\\Release\\HookFinder.exe");
	staticparse::Pe_Parser parse("C:\\Users\\Cole\\Documents\\putty.exe");

	parse.Parse();
	staticparse::ExtractInfo exInfo = parse.ParsedInfo;

	std::cout << "filename: " << exInfo.FileName << std::endl;
	std::cout << "file size: " << exInfo.FileSize << std::endl;
	std::cout << "md5: " << exInfo.HashInfo.MD5 << std::endl;
	std::cout << "sha1: " << exInfo.HashInfo.SHA1 << std::endl;
	std::cout << "sha256: " << exInfo.HashInfo.SHA256 << std::endl;

	std::cout << std::endl;

	for (auto& s : exInfo.Sections)
	{
		std::cout << "Section name: " << s.SectionName << std::endl;
		std::cout << "Section Raw Size: " << s.SizeOfRawData << std::endl;
		std::cout << "md5: " << s.HashInfo.MD5 << std::endl;
		std::cout << "sha1: " << s.HashInfo.SHA1 << std::endl;
		std::cout << "sha256: " << s.HashInfo.SHA256 << std::endl;


		printf("\n");
	}
	std::cout << std::endl;
	std::cout << std::endl;


	for (const auto& lib : exInfo.Imports)
	{
		for (const auto& func : lib.second)
		{
			std::cout << lib.first << ": " << func << std::endl;
		}
	}
}


int main()
{
	
	//zip_manager z;
	//z.Unzip_Password_ProtectedFile((LPSTR)"C:\\Users\\Cole\\Documents\\putty.zip", (LPSTR)"putty.exe", nullptr, (LPSTR)"C:\\Users\\Cole\\Documents\\bigmeme.exe");
	staticparse::Pe_Parser parse("C:\\Users\\Cole\\Documents\\putty.exe");

	parse.Parse();
	staticparse::ExtractInfo exInfo = parse.ParsedInfo;
	Event<FileParseEvent> fp;
	fp.Entry = (PlEntry)&fp;
	fp.Data.ParseInfo = exInfo;

	json data = eventparser::ParseFileParseEvent(&fp);
	std::cout << data.dump().c_str() << std::endl;
}	