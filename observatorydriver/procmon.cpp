#include "procmon.h"
#pragma warning(disable: 4311)
#pragma warning(disable: 4302)
#pragma warning(disable: 4701)

extern Globals g_Struct;

void procmon::OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    // If a monitored file has not  been given to the driver, there is nothing to do
    if (IsListEmpty(&g_Struct.MonitoredFiles))
    {
        return;
    }
    UNICODE_STRING ParentProcess;
    ParentProcess.Buffer = nullptr;
    if (CreateInfo)
    {
        bool found_pid = FALSE;
        if (CreateInfo->FileOpenNameAvailable)
        {

            while (true)
            {
                FastMutex lock(g_Struct.MonitoredFilesMutex);   // We have to do it this way so we can push it without a double acquire
                lock.Lock();
                MonitoredFile* mf_struct = CONTAINING_RECORD(g_Struct.EventsHead.Flink, MonitoredFile, Entry);
                while (true)
                {
                    if (mf_struct->PID == (ULONG)CreateInfo->ParentProcessId)
                    {
                        auto new_monitored_file = (MonitoredFile*)ExAllocatePoolWithTag(NonPagedPool, sizeof(MonitoredFile), DRIVER_TAG);
                        if (new_monitored_file == nullptr)
                        {
                            return;
                        }

                        RtlInitUnicodeString(&new_monitored_file->FilePath, CreateInfo->ImageFileName->Buffer);
                        new_monitored_file->PID = (ULONG)ProcessId;
                        lock.Unlock();

                        PushMonitoredFile(&new_monitored_file->Entry, &g_Struct.MonitoredFiles, g_Struct.MonitoredFilesMutex, g_Struct.MonitoredFilesCount);


                        RtlInitUnicodeString(&ParentProcess, mf_struct->FilePath.Buffer);
                        found_pid = TRUE;
                        break;
                    }

                    LIST_ENTRY* next = mf_struct->Entry.Flink;
                    if (next == &g_Struct.EventsHead)
                    {
                        break;
                    }
                    mf_struct = CONTAINING_RECORD(next, MonitoredFile, Entry);
                }
                break;
            }



            if (!found_pid)
            {
                return;
            }
            ULONG AllocSize = 0;
            AllocSize += sizeof(Event<ProcessEvent>);
            AllocSize += ParentProcess.Length + 1;
            AllocSize += CreateInfo->ImageFileName->Length + 1;

            auto NewEvent = (Event<ProcessEvent>*)ExAllocatePoolWithTag(NonPagedPool, AllocSize, DRIVER_TAG);
            memset(NewEvent, 0x00, AllocSize);
            BYTE* WritePtr = (BYTE*)NewEvent + sizeof(NewEvent);
            if (NewEvent == nullptr)
            {
                return;
            }

            auto& data = NewEvent->Data;

            data.Type = EventType::ProcessEvent;
            KeQuerySystemTime(&data.Timestamp);
            data.Pid = (ULONG)ProcessId;
            data.ParentPid = (ULONG)CreateInfo->ParentProcessId;
            data.ParentNameLength = ParentProcess.Length;
            data.ImageFileNameLength = CreateInfo->ImageFileName->Length;
            data.Size = AllocSize;
            data.OffsetImageFileName = sizeof(NewEvent);
            data.OffsetParentName = sizeof(NewEvent) + CreateInfo->ImageFileName->Length + 1;
            memcpy(WritePtr, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
            WritePtr += CreateInfo->ImageFileName->Length + 1;
            memcpy(WritePtr, ParentProcess.Buffer, ParentProcess.Length);

            PushEvent(&NewEvent->Entry, &g_Struct.EventsHead, g_Struct.EventsMutex, g_Struct.EventCount);
        }
    }

    return;
}