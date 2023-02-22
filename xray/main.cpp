#include <Windows.h>

#include <stdlib.h>
#include <iostream>

#include "raii.h"
#include "fileparser.h"
#include "infrastructure.h"
#include "zipClass.h"
#include "manager.h"
using namespace nlohmann;




Globals g_Struct;




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



struct s {
	lEntry Entry;
	int num;
};

int main(int argc, char* argv[])
{

	InitializeListHeader(&g_Struct.ReadEvents);
	
	g_Struct.ReadEventsMutex = CreateMutexA(0, 0, 0);

	s newEnt;
	newEnt.num = 1;


	//PushEntry(g_Struct.ReadEvents, &newEnt.Entry);
	//auto one = PopEntry(g_Struct.ReadEvents);
	//auto two = PopEntry(g_Struct.ReadEvents);
	
	//if (two == &g_Struct.ReadEvents->Entry)
	//{
	//	printf("Equal. 0x%p  == 0x%p\n", one, two, &g_Struct.ReadEvents);
	//}




	//Url url = std::string("http://192.168.86.48/api");

	//json parsed = { {"test", "Swag"} };


	//Response r = Post(url, Body{ parsed.dump() }, Header{ {"Content-Type", "application/json"} });



	auto Manager = new manager((char*)"192.168.86.48");
	while (!Manager->CheckExit())
	{
		printf("Not done..\n");
		Sleep(2000);
	}
}	