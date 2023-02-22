#pragma once
#include "infrastructure.h"

typedef NTSTATUS(*QUERY_INFO_PROCESS)(
	__in HANDLE                                      ProcessHandle,
	__in PROCESSINFOCLASS                            ProcessInformationClass,
	__out_bcount_opt(ProcessInformationLength) PVOID ProcessInformation,
	__in UINT32                                      ProcessInformationLength,
	__out_opt PUINT32                                ReturnLength
	);

namespace procmon
{
	void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
	bool CheckIfMonitoredPID(LIST_ENTRY* MonitoredFileEntry, ULONG PID, FastMutex& Mutex);
}

