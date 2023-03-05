#pragma once
#include "helpers.h"



namespace procmon
{
	void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
	bool CheckIfMonitoredPID(LIST_ENTRY* MonitoredFileEntry, ULONG PID, FastMutex& Mutex);
}

