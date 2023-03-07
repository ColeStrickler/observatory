#include "fsmon.h"
/*++

Module Name:

    observatorydriver.c

Abstract:

    This is the main module of the observatorydriver miniFilter driver.

Environment:

    Kernel mode

--*/


extern Globals g_Struct;
static QUERY_INFO_PROCESS ZwQueryInformationProcess = nullptr;

/*
static USHORT GetFileCreationDisposition(ULONG Create_Options)
{
    return (Create_Options >> 24) & 0xff;
};
*/



ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))


/*************************************************************************
    Prototypes
*************************************************************************/
EXTERN_C_START





VOID
DeleteProtectOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
DeleteProtectPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
DeleteProtectPreOperationNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

BOOLEAN
DeleteProtectDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
);




EXTERN_C_END


//
//  Assign text sections for each routine.
//



//
//  operation registration
//
_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS __stdcall fsmon::PreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    PVOID*
)
{
    UNREFERENCED_PARAMETER(FltObjects);

    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    auto& params = Data->Iopb->Parameters.SetFileInformation;

    if (params.FileInformationClass != FileDispositionInformation && params.FileInformationClass != FileDispositionInformationEx) {
        // not a delete operation
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    auto info = (FILE_DISPOSITION_INFORMATION*)params.InfoBuffer;
    if (!info->DeleteFile) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    // FOR THIS MAJOR FUNCTION AND MANY OTHERS,THIS CALLBACK IS NOT HAPPENING IN THE REQUESTING THREAD
    // WE WILL USE THE Thread FIELD TO ACCESS THE ORIGINAL CALLER
    auto process = PsGetThreadProcess(Data->Thread);
    NT_ASSERT(process);

    HANDLE hProc;
    auto status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, 0, nullptr, KernelMode, &hProc);
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    auto size = 1000;
    auto procName = (UNICODE_STRING*)ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
    if (procName) 
    {
        auto pid = HandleToUlong(hProc);

        if (procmon::CheckIfMonitoredPID(&g_Struct.MonitoredFiles, pid, g_Struct.MonitoredFilesMutex))
        {
            memset(procName, 0, size);
            if (ZwQueryInformationProcess == nullptr)
            {
                if (!helpers::ResolveSystemFunction((void**)&ZwQueryInformationProcess, L"ZwQueryInformationProcess"))
                {
                    KdPrint(("fsmon::PreSetInformation() --> Unable to resolve ZwQueryInformationProcess\n"));
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }
            }
            status = ZwQueryInformationProcess(hProc, ProcessImageFileName, procName, size - sizeof(WCHAR), nullptr);
            if (!NT_SUCCESS(status)) {
                if (hProc) {
                    ZwClose(hProc);
                }
                ExFreePool(procName);
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }

            PFLT_FILE_NAME_INFORMATION NameInfo;
            status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED, &NameInfo);
            if (!NT_SUCCESS(status)) {
                if (hProc) {
                    ZwClose(hProc);
                }
                ExFreePool(procName);
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }



            auto allocSize = sizeof(Event<FileEvent>) + NameInfo->Name.Length + procName->Length;
            auto evt = (Event<FileEvent>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
            if (!evt)
            {
                FltReleaseFileNameInformation(NameInfo);
                ExFreePool(procName);
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }

            FileEvent& data = evt->Data;


            data.Type = EventType::FileEvent;
            data.Size = sizeof(FileEvent) + NameInfo->Name.Length + procName->Length;
            KeQuerySystemTime(&data.Timestamp);
            data.PathLength = NameInfo->Name.Length;
            data.ProcessLength = procName->Length;
            data.Pid = pid;
            data.OffsetProcess = sizeof(FileEvent);
            data.OffsetPath = sizeof(FileEvent) + procName->Length;
            data.Action = FileEventType::Delete;


            BYTE* writePtr = (BYTE*)evt + sizeof(Event<FileEvent>);
            memcpy(writePtr, procName->Buffer, procName->Length);
            writePtr += procName->Length;
            memcpy(writePtr, NameInfo->Name.Buffer, NameInfo->Name.Length);
            PushEvent(&evt->Entry, &g_Struct.EventsHead, g_Struct.EventsMutex, g_Struct.EventCount);

            ExFreePool(procName);
            FltReleaseFileNameInformation(NameInfo);    
        }
 
    }
    if (hProc) {
        ZwClose(hProc);
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}











_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS __stdcall fsmon::PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
)
{
    
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);


    if (Data->RequestorMode == KernelMode) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    

    const auto& params = Data->Iopb->Parameters.Create;
    
    auto size = 1000;
        auto procName = (UNICODE_STRING*)ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
        if (procName == nullptr) {
            KdPrint(("fsmon::PreCreate() --> could not allocate pool\n"));
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        RtlZeroMemory(procName, size);
        


        if (ZwQueryInformationProcess == nullptr)
        {
            if (!helpers::ResolveSystemFunction((void**)&ZwQueryInformationProcess, L"ZwQueryInformationProcess"))
            {
                KdPrint(("fsmon::PreCreate() --> Unable to resolve ZwQueryInformationProcess\n"));
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }
        }
        
     
        
        auto status = ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, procName, size - sizeof(WCHAR), nullptr);
        
        if (!NT_SUCCESS(status))
        {
            KdPrint(("fsmon::PreCreate() --> ZwQueryInformationProcess failed!\n"));
            ExFreePool(procName);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }


        ULONG pid = HandleToUlong(PsGetCurrentProcessId());
        if (procmon::CheckIfMonitoredPID(g_Struct.MonitoredFiles.Flink, pid, g_Struct.MonitoredFilesMutex))
        {
            if (params.Options & FILE_NON_DIRECTORY_FILE)
            {
                PFLT_FILE_NAME_INFORMATION NameInfo;
                status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED, &NameInfo);
                if (!NT_SUCCESS(status))
                {
                    ExFreePool(procName);
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }

                // in procmon we gave two extra bytes in the allocation, but they seem unneeded
                auto allocSize = sizeof(Event<FileEvent>) + NameInfo->Name.Length + procName->Length;

                auto evt = (Event<FileEvent>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
                if (!evt)
                {
                    FltReleaseFileNameInformation(NameInfo);
                    ExFreePool(procName);
                    return FLT_PREOP_SUCCESS_NO_CALLBACK;
                }

                FileEvent& data = evt->Data;


                data.Type = EventType::FileEvent;
                data.Size = sizeof(FileEvent) + NameInfo->Name.Length + procName->Length;
                KeQuerySystemTime(&data.Timestamp);
                data.PathLength = NameInfo->Name.Length;
                data.ProcessLength = procName->Length;
                data.Pid = pid;
                data.OffsetProcess = sizeof(FileEvent);
                data.OffsetPath = sizeof(FileEvent) + procName->Length;
                
               // USHORT Mask = FILE_SUPERSEDED | FILE_CREATE | FILE_OVERWRITE | FILE_OVERWRITE_IF;
                //ULONG Disposition = GetFileCreationDisposition(Data->Iopb->Parameters.Create.Options);
                KdPrint(("%wZ -> %wZ Mask: 0x%x\n", procName, NameInfo->Name, Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess));
                if (params.Options & FILE_DELETE_ON_CLOSE)
                {
                    data.Action = FileEventType::Delete;
                }
                else if (Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (WRITE_DAC | GENERIC_WRITE | WRITE_OWNER | FILE_APPEND_DATA | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES\
                    | FILE_WRITE_EA))
                {
                    data.Action = FileEventType::Write;
                }
                else
                {
                    data.Action = FileEventType::Read;
                }


                BYTE* writePtr = (BYTE*)evt + sizeof(Event<FileEvent>);
                memcpy(writePtr, procName->Buffer, procName->Length);
                writePtr += procName->Length;
                memcpy(writePtr, NameInfo->Name.Buffer, NameInfo->Name.Length);
                PushEvent(&evt->Entry, &g_Struct.EventsHead, g_Struct.EventsMutex, g_Struct.EventCount);
                FltReleaseFileNameInformation(NameInfo);
                ExFreePool(procName);
            }
            
        }


    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}



    
    









_Use_decl_annotations_
NTSTATUS __stdcall fsmon::InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DeleteProtect!DeleteProtectInstanceSetup: Entered\n"));

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS __stdcall fsmon::InstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DeleteProtect!DeleteProtectInstanceQueryTeardown: Entered\n"));

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
__stdcall fsmon::InstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DeleteProtect!DeleteProtectInstanceTeardownStart: Entered\n"));
}

_Use_decl_annotations_
VOID
_stdcall fsmon::InstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DeleteProtect!DeleteProtectInstanceTeardownComplete: Entered\n"));
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/
NTSTATUS
DriverEntry2(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DeleteProtect!DriverEntry: Entered\n"));

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter(DriverObject,
        &FilterRegistration,
        &g_Struct.gFilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status)) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering(g_Struct.gFilterHandle);

        if (!NT_SUCCESS(status)) {

            FltUnregisterFilter(g_Struct.gFilterHandle);
        }
    }

    return status;
}

NTSTATUS
__stdcall fsmon::Unload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DeleteProtect!DeleteProtectUnload: Entered\n"));

    FltUnregisterFilter(g_Struct.gFilterHandle);

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/



VOID
DeleteProtectOperationStatusCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
)
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(FltObjects);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DeleteProtect!DeleteProtectOperationStatusCallback: Entered\n"));

    PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
        ("DeleteProtect!DeleteProtectOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
            OperationStatus,
            RequesterContext,
            ParameterSnapshot->MajorFunction,
            ParameterSnapshot->MinorFunction,
            FltGetIrpName(ParameterSnapshot->MajorFunction)));
}


FLT_POSTOP_CALLBACK_STATUS
DeleteProtectPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DeleteProtect!DeleteProtectPostOperation: Entered\n"));

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
DeleteProtectPreOperationNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("DeleteProtect!DeleteProtectPreOperationNoPostOperation: Entered\n"));

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
DeleteProtectDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
)
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

        //
        //  Check for oplock operations
        //

        (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
            ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

            ||

            //
            //    Check for directy change notification
            //

            ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
                (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
            );
}