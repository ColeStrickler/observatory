#pragma once
#include "infrastructure.h"



namespace procmon
{
	void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
}

