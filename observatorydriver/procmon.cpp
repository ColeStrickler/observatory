#include "procmon.h"
#pragma warning(disable: 4311)
#pragma warning(disable: 4302)
#pragma warning(disable: 4701)

extern Globals g_Struct;
static QUERY_INFO_PROCESS ZwQueryInformationProcess = nullptr;;



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
    UNREFERENCED_PARAMETER(Process);

    // If a monitored file has not  been given to the driver, there is nothing to do
    if (IsListEmpty(&g_Struct.MonitoredFiles))
    {
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
                // PID will be set to zero for the initial process, we will set the pid of the structure properly and then return for the initial monitored file
                if (mf_struct->PID == 0)
                {
                    if (!RtlCompareUnicodeString(&mf_struct->FilePath, CreateInfo->ImageFileName, TRUE))
                    {
                        mf_struct->PID = HandleToULong(ProcessId);
                        return;
                    }
                    return;
                }

                
                while (true)
                {
                    if (mf_struct->PID == HandleToULong(CreateInfo->ParentProcessId))
                    {
                        auto new_monitored_file = (MonitoredFile*)ExAllocatePoolWithTag(NonPagedPool, sizeof(MonitoredFile), DRIVER_TAG);
                        if (new_monitored_file == nullptr)
                        {
                            return;
                        }

                        RtlInitUnicodeString(&new_monitored_file->FilePath, CreateInfo->ImageFileName->Buffer);
                        new_monitored_file->PID = HandleToULong(ProcessId);
                        // we have to destroy the lock here to prevent a deadlock
                        PushMonitoredFile(&new_monitored_file->Entry, &g_Struct.MonitoredFiles, g_Struct.MonitoredFilesCount);


                        PEPROCESS PeParentProc = nullptr;
                        NTSTATUS status = PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &PeParentProc);
                        PUNICODE_STRING parent_proc_name = nullptr;
                        
                        if (NT_SUCCESS(status)) {
                            status = helpers::GetProcessImageName(PeParentProc, &parent_proc_name);
                            if (!NT_SUCCESS(status))
                            {
                                KdPrint(("Unable to get Parent Process name!\n"));
                                break;
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
                        
                        found_pid = TRUE;
                        break;
                    }

                    LIST_ENTRY* next = mf_struct->Entry.Flink;
                    if (next == &g_Struct.MonitoredFiles)
                    {
                        break;
                    }
                    mf_struct = CONTAINING_RECORD(next, MonitoredFile, Entry);
                }
                break;
            }
        }
    }

    return;
}