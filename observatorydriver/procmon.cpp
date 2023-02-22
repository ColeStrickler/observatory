#include "procmon.h"
#pragma warning(disable: 4311)
#pragma warning(disable: 4302)
#pragma warning(disable: 4701)

extern Globals g_Struct;

static QUERY_INFO_PROCESS ZwQueryInformationProcess;


NTSTATUS
GetProcessImageName(
    PEPROCESS eProcess,
    PUNICODE_STRING* ProcessImageName
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UINT32 returnedLength;
    HANDLE hProcess = NULL;

    PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

    if (eProcess == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    status = ObOpenObjectByPointer(eProcess,
        0, NULL, 0, 0, KernelMode, &hProcess);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
        return status;
    }

    if (ZwQueryInformationProcess == NULL)
    {
        UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");

        ZwQueryInformationProcess =
            (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

        if (ZwQueryInformationProcess == NULL)
        {
            DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
            status = STATUS_UNSUCCESSFUL;
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
        DbgPrint("ZwQueryInformationProcess status = %x\n", status);
        goto cleanUp;
    }

    *ProcessImageName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, returnedLength, DRIVER_TAG);

    if (ProcessImageName == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanUp;
    }

    /* Retrieve the process path from the handle to the process */
    status = ZwQueryInformationProcess(hProcess,
        ProcessImageFileName,
        *ProcessImageName,
        returnedLength,
        &returnedLength);

    if (!NT_SUCCESS(status)) ExFreePool(*ProcessImageName);

cleanUp:

    ZwClose(hProcess);

    return status;
}



bool procmon::CheckIfMonitoredPID(LIST_ENTRY* MonitoredFileEntry, ULONG PID, FastMutex& Mutex)
{
    AutoLock<FastMutex> lock(Mutex);
    if (IsListEmpty(&g_Struct.MonitoredFiles))
    {
        return false;
    }

    auto curr = CONTAINING_RECORD(MonitoredFileEntry, MonitoredFile, Entry);
    
    while((uintptr_t)curr != (uintptr_t)&g_Struct.MonitoredFiles)
    {
        if (curr->PID == PID)
        {
            return true;
        }
        curr = CONTAINING_RECORD(curr->Entry.Flink, MonitoredFile, Entry);
    }
    return false;
}


void procmon::OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (CreateInfo) {
        if (CreateInfo->FileOpenNameAvailable)
        {
            KdPrint(("%wZ\n", CreateInfo->ImageFileName));
        }
    }
    
    
    UNREFERENCED_PARAMETER(Process);

    // If a monitored file has not  been given to the driver, there is nothing to do
    if (IsListEmpty(&g_Struct.MonitoredFiles))
    {
        KdPrint(("No monitored files. No work to do.\n"));
        return;
    }

    if (CreateInfo)
    {
        bool found_pid = FALSE;
        if (CreateInfo->FileOpenNameAvailable)
        {
            
            while (true)
            {
                // We can probably optimize this locking scheme
                AutoLock<FastMutex> lock(g_Struct.MonitoredFilesMutex);
                MonitoredFile* mf_struct = CONTAINING_RECORD(g_Struct.MonitoredFiles.Flink, MonitoredFile, Entry);
                if (mf_struct->PID == 0)
                {
                    if (!RtlCompareUnicodeString(&mf_struct->FilePath, CreateInfo->ImageFileName, TRUE))
                    {
                        KdPrint(("Found initial monitored file. Setting PID.\n"));
                        mf_struct->PID = HandleToULong(ProcessId);
                        return;
                    }
                    KdPrint(("Wrong proc\n"));
                    return;
                }

                
                while (true)
                {
                    KdPrint(("Comparing %wZ vs. %wZ\n", mf_struct->FilePath, CreateInfo->ImageFileName));
                    if (mf_struct->PID == HandleToULong(CreateInfo->ParentProcessId))
                    {
                        KdPrint(("Allocating events..\n"));
                        auto new_monitored_file = (MonitoredFile*)ExAllocatePoolWithTag(NonPagedPool, sizeof(MonitoredFile), DRIVER_TAG);
                        if (new_monitored_file == nullptr)
                        {
                            KdPrint(("allocation error. returning..\n"));
                            return;
                        }

                        RtlInitUnicodeString(&new_monitored_file->FilePath, CreateInfo->ImageFileName->Buffer);
                        new_monitored_file->PID = HandleToULong(ProcessId);
                        // we have to destroy the lock here to prevent a deadlock
                        PushMonitoredFile(&new_monitored_file->Entry, &g_Struct.MonitoredFiles, g_Struct.MonitoredFilesCount);
                        KdPrint(("Pushed monitored file.\n"));


                        PEPROCESS PeParentProc = nullptr;
                        NTSTATUS status = PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &PeParentProc);
                        PUNICODE_STRING parent_proc_name = nullptr;
                        
                        KdPrint(("Attempting to get Parent ProcName\n"));
                        if (NT_SUCCESS(status)) {
                            status = GetProcessImageName(PeParentProc, &parent_proc_name);
                            if (NT_SUCCESS(status)) {
                                KdPrint(("Got parent process name : %wZ\n", parent_proc_name));
                            }
                        }
                        


                        ULONG allocSize = sizeof(Event<ProcessEvent>);
                        allocSize += CreateInfo->ImageFileName->Length + 1;
                        allocSize += parent_proc_name->Length + 1;


                        auto new_event = (Event<ProcessEvent>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
                        memset(new_event, 0x00, allocSize);
                        auto& data = new_event->Data;
                        data.Type = EventType::ProcessEvent;
                        KeQuerySystemTime(&data.Timestamp);
                        data.Pid = HandleToULong(ProcessId);
                        data.ImageFileNameLength = CreateInfo->ImageFileName->Length;
                        data.ParentPid = HandleToULong(CreateInfo->ParentProcessId);
                        data.ParentNameLength = parent_proc_name->Length;
                        data.Size = sizeof(ProcessEvent) + parent_proc_name->Length + CreateInfo->ImageFileName->Length;


                        BYTE* writePtr = (BYTE*)new_event + sizeof(Event<ProcessEvent>);

                        if (CreateInfo->ImageFileName->Length > 0)
                        {
                            data.OffsetImageFileName = sizeof(ProcessEvent);
                            memcpy(writePtr, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
                            writePtr += CreateInfo->ImageFileName->Length;
                        }

                        else {
                            data.OffsetImageFileName = 0;
                        }

                        if (parent_proc_name->Length > 0)
                        {
                            data.OffsetParentName = sizeof(ProcessEvent) + CreateInfo->ImageFileName->Length;
                            memcpy(writePtr, parent_proc_name->Buffer, parent_proc_name->Length);
                        }
                        else 
                        {
                            data.OffsetParentName = 0;
                        }
                        PushEvent(&new_event->Entry, &g_Struct.EventsHead, g_Struct.EventsMutex, g_Struct.EventCount);
                        KdPrint(("Just pushed event!\n"));
                        
                        found_pid = TRUE;
                        break;
                    }

                    LIST_ENTRY* next = mf_struct->Entry.Flink;
                    if (next == &g_Struct.MonitoredFiles)
                    {
                        KdPrint(("found head. BREAKING!\n"));
                        break;
                    }
                    mf_struct = CONTAINING_RECORD(next, MonitoredFile, Entry);
                }
                KdPrint(("\nbreaking  out process handler..\n"));
                break;
            }
        }
    }

    return;
}