#pragma once
#include "helpers.h"

static QUERY_INFO_PROCESS ZwQueryInformationProcess = nullptr;

bool helpers::ResolveSystemFunction(void** Function, const wchar_t* FuncName)
{
    if (*Function == NULL)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, FuncName);

        *Function =
            (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

        if (*Function == NULL)
        {
            return false;
        }

        return true;
    }
    return true;
}



NTSTATUS helpers::GetProcessImageName(PEPROCESS eProcess, PUNICODE_STRING* ProcessImageName)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32 returnedLength;
    HANDLE hProcess = NULL;

    PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

    if (eProcess == NULL)
    {
        KdPrint(("helpers::GetProcessImageName() --> null EProcess\n"));
        return STATUS_INVALID_PARAMETER_1;
    }

    status = ObOpenObjectByPointer(eProcess,
        0, NULL, 0, 0, KernelMode, &hProcess);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("helpers::GetProcessImageName() --> unable to open object pointer\n"));
        return status;
    }

    if (ZwQueryInformationProcess == NULL)
    {
        if (!helpers::ResolveSystemFunction((void**)&ZwQueryInformationProcess, L"ZwQueryInformationProcess"))
        {
            KdPrint(("Could not resolve system function ZwQueryInformationProcess\n"));
            status = STATUS_ABANDONED;
            goto cleanUp;
        }
    }

    /* Query the actual size of the process path */
    status = ZwQueryInformationProcess(hProcess,
        ProcessImageFileName,
        NULL, // buffer
        0,    // buffer size
        &returnedLength);

    if (STATUS_INFO_LENGTH_MISMATCH != status) {
        KdPrint(("helpers::GetProcessImageName() --> length mismatch\n"));
        goto cleanUp;
    }

    *ProcessImageName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, returnedLength, DRIVER_TAG);

    if (ProcessImageName == NULL)
    {
        KdPrint(("helpers::GetProcessImageName() --> insufficient resources\n"));
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanUp;
    }

    /* Retrieve the process path from the handle to the process */
    status = ZwQueryInformationProcess(hProcess,
        ProcessImageFileName,
        *ProcessImageName,
        returnedLength,
        &returnedLength);

    if (!NT_SUCCESS(status))
    {
        KdPrint(("helpers::GetProcessImageName() --> ZwQueryInformationProcess fail!\n"));
        ExFreePool(*ProcessImageName);
    }
cleanUp:

    ZwClose(hProcess);
    return status;
}