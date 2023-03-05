#pragma once
#include "infrastructure.h"

typedef NTSTATUS(*QUERY_INFO_PROCESS)(
	__in HANDLE                                      ProcessHandle,
	__in PROCESSINFOCLASS                            ProcessInformationClass,
	__out_bcount_opt(ProcessInformationLength) PVOID ProcessInformation,
	__in UINT32                                      ProcessInformationLength,
	__out_opt PUINT32                                ReturnLength
	);



namespace helpers
{
	// Our Defined Functions
	NTSTATUS GetProcessImageName(PEPROCESS eProcess, PUNICODE_STRING* ProcessImageName);
	bool ResolveSystemFunction(void** Function, const wchar_t* FuncName);




}


