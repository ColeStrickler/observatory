#pragma once
#include <Windows.h>
#include <string>
#include "raii.h"

#define stringify( name ) #name

std::string DisplayTime(const LARGE_INTEGER& time);
std::string WstringToString(std::wstring wstr);
std::string BinaryToString(void* Tgt, DWORD Length);