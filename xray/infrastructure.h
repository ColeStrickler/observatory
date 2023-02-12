#pragma once
#include "LinkedList.h"
#include <Windows.h>

typedef struct Globals
{
	PListHeader ReadEvents;
	HANDLE		ReadEventsMutex;
}PGlobals;