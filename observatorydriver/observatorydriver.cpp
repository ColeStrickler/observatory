#include "infrastructure.h"
#pragma warning(disable: 4311)
#pragma warning(disable: 4302)


void UnloadObservatoryDriver(PDRIVER_OBJECT DriverObject);
NTSTATUS WriteMonitoredFile(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS ReadEvents(PDEVICE_OBJECT, PIRP Irp);
NTSTATUS CreateClose(PDEVICE_OBJECT, PIRP Irp);



Globals g_Struct;


extern "C" NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    auto status = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = nullptr;
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\observatorydriver");
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\device\\observatorydriver");

    // Bools
    bool SymLinkCreated =           FALSE;
    bool ProcessCallbacks =         FALSE;
    



    // Initialize Linked Lists
    InitializeListHead(&g_Struct.EventsHead);
    InitializeListHead(&g_Struct.MonitoredFiles);


    // Initialize Mutexes
    g_Struct.EventsMutex.Init();
    g_Struct.MonitoredFilesMutex.Init();

    do
    {
        status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
        if (!NT_SUCCESS(status)) {
            KdPrint(("DriverEntry: Failed to create device (0x%08X)\n", status));
            break;
        }

        // use DIRECT IO because we will be passing in large buffers and want to avoid copies
        DeviceObject->Flags |= DO_DIRECT_IO;

        status = IoCreateSymbolicLink(&symLink, &devName);
        if (!NT_SUCCESS(status)) {
            KdPrint(("DriverEntry: failed to create sym link (0x%08X)\n", status));
            break;
        }
        SymLinkCreated = true;

        status = PsSetCreateProcessNotifyRoutineEx(procmon::OnProcessNotify, FALSE);
        if (!NT_SUCCESS(status)) {
            KdPrint(("DriverEntry: failed to register process callback (0x%08X)\n", status));
            break;
        }
        ProcessCallbacks = true;




    } while (FALSE);

    // Cleanup upon failure
    if (!NT_SUCCESS(status))
    {
        
        if (ProcessCallbacks)
        {
            PsSetCreateProcessNotifyRoutineEx(procmon::OnProcessNotify, TRUE);
        }
            
        if (SymLinkCreated)
        {
            IoDeleteSymbolicLink(&symLink);
        }

        if (DeviceObject)
        {
            IoDeleteDevice(DeviceObject);
        }

    }

    DriverObject->DriverUnload = UnloadObservatoryDriver;
    DriverObject->MajorFunction[IRP_MJ_READ] = ReadEvents;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = WriteMonitoredFile;
    //DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;

    KdPrint(("DriverEntry: finished."));
    return status;
}


void UnloadObservatoryDriver(PDRIVER_OBJECT DriverObject)
{


    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\observatorydriver");
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
    PsSetCreateProcessNotifyRoutineEx(procmon::OnProcessNotify, TRUE);

    while (!IsListEmpty(&g_Struct.EventsHead))
    {
        auto entry = RemoveHeadList(&g_Struct.EventsHead);
        short type = *(short*)((UINT64)entry + sizeof(LIST_ENTRY));

        switch (type)
        {
            case (short)EventType::FileEvent:
            {
                ExFreePool(CONTAINING_RECORD(entry, Event<FileEvent>, Entry));
                break;
            }

            case (short)EventType::NetworkEvent:
            {
                ExFreePool(CONTAINING_RECORD(entry, Event<NetworkEvent>, Entry));
                break;
            }

            case (short)EventType::ProcessEvent:
            {
                ExFreePool(CONTAINING_RECORD(entry, Event<ProcessEvent>, Entry));
                break;
            }

            case (short)EventType::ImageLoadEvent:
            {
                ExFreePool(CONTAINING_RECORD(entry, Event<ImageLoadEvent>, Entry));
                break;
            }

            case (short)EventType::ThreadEvent:
            {
                ExFreePool(CONTAINING_RECORD(entry, Event<ThreadEvent>, Entry));
                break;
            }

            case (short)EventType::RemoteThreadEvent:
            {
                ExFreePool(CONTAINING_RECORD(entry, Event<RemoteThreadEvent>, Entry));
                break;
            }

            case (short)EventType::RegistryEvent:
            {
                ExFreePool(CONTAINING_RECORD(entry, Event<RegistryEvent>, Entry));
                break;
            }

            case (short)EventType::ObjectCallbackEvent:
            {
                ExFreePool(CONTAINING_RECORD(entry, Event<ObjectCallbackEvent>, Entry));
                break;
            }
        }
    }

    while (!IsListEmpty(&g_Struct.MonitoredFiles))
    {
        auto entry = RemoveHeadList(&g_Struct.MonitoredFiles);
        ExFreePool(CONTAINING_RECORD(entry, MonitoredFile, Entry));
    }



    KdPrint(("UnloadObservatoryDriver: Unload Successful."));
}


NTSTATUS WriteMonitoredFile(PDEVICE_OBJECT, PIRP Irp)
{
    if (!IsListEmpty(&g_Struct.MonitoredFiles))             // We only want to take one input at a time
    {
        return STATUS_ALREADY_COMPLETE;
    }

    //auto stack = IoGetCurrentIrpStackLocation(Irp);
    //auto len = stack->Parameters.Write.Length;
    auto status = STATUS_SUCCESS;

    NT_ASSERT(Irp->MdlAddress);
    auto buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    if (!buffer)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        KdPrint(("Begin monitoring file: %s\n", (char*)buffer));
        auto NewMonitoredFile = (MonitoredFile*)ExAllocatePoolWithTag(NonPagedPool, sizeof(MonitoredFile), DRIVER_TAG);
        if (NewMonitoredFile == nullptr)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NewMonitoredFile->PID = 0;

        charToUnicodeString((char*)buffer, NewMonitoredFile->FilePath);
        KdPrint(("Begin Monitoring File: %wZ\n", &NewMonitoredFile->FilePath));
        PushMonitoredFile(&NewMonitoredFile->Entry, &g_Struct.MonitoredFiles, g_Struct.MonitoredFilesMutex, g_Struct.MonitoredFilesCount);
    }
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}


/*
    This function is used by the usermode component to read events generated by the producers
*/
NTSTATUS ReadEvents(PDEVICE_OBJECT, PIRP Irp)
{
    // If a monitored file has not  been given to the driver, there is nothing to do
    if (IsListEmpty(&g_Struct.MonitoredFiles))
    {
        return STATUS_NONE_MAPPED;
    }


    auto stack = IoGetCurrentIrpStackLocation(Irp);
    auto len = stack->Parameters.Read.Length;
    auto status = STATUS_SUCCESS;
    auto count = 0;

    // ENSURE THIS EXISTS BECAUSE WERE USING DIRECT IO
    NT_ASSERT(Irp->MdlAddress);

    auto buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
    if (!buffer) 
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }
    else
    {
        AutoLock<FastMutex> lock(g_Struct.EventsMutex);
        while (true)
        {
            if (IsListEmpty(&g_Struct.EventsHead))
            {
                KdPrint(("Events is empty on Read.\n"));
                break;
            }
            else {
                KdPrint(("Copying over events...\n"));
            }

            auto entry = RemoveHeadList(&g_Struct.EventsHead);
            auto info = CONTAINING_RECORD(entry, Event<EventHeader>, Entry);
            auto size = info->Data.Size;

            if (len < size)
            {
                // user buffer is too full to take another, put item back
                InsertHeadList(&g_Struct.EventsHead, entry);
                break;
            }

            
            memcpy(buffer, &info->Data, size);

            g_Struct.EventCount--;
            len -= size;
            buffer += size;
            count += size;

            ExFreePool(info); // free the whole structure
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = count;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;

}

NTSTATUS CreateClose(PDEVICE_OBJECT, PIRP Irp) {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, 0);
    return STATUS_SUCCESS;
}

