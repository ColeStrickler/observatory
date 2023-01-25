#pragma once
#include <Windows.h>
#include <vector>
#include <zip.h>
#include "raii.h"
#include "const.h"



class zip_manager
{
public:
	zip_t* windows_open(const char* name, int flags);
	void Unzip_Password_ProtectedFile(LPSTR FilePath, LPSTR FileName, LPSTR Password, LPSTR OutPath);

public:
	std::vector<DWORD> Errors;

};

