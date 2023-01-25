#pragma once
#include <Windows.h>
#include <string>
#define stringify( name ) #name

std::string DisplayTime(const LARGE_INTEGER& time);