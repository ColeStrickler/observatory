#pragma once
#include <fltKernel.h>
#include <dontuse.h>
#include "procmon.h"
#include "helpers.h"
#pragma warning( disable : 4996)
#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

namespace fsmon
{

    // CALLBACKS
    FLT_PREOP_CALLBACK_STATUS __stdcall PreCreate(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _Outptr_result_maybenull_ PVOID* CompletionContext
    );


    FLT_PREOP_CALLBACK_STATUS __stdcall PreSetInformation(
        _Inout_ PFLT_CALLBACK_DATA Data,
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        PVOID*
    );
    


    // Helpers
    






    // Setup
    NTSTATUS __stdcall InstanceSetup(
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
        _In_ DEVICE_TYPE VolumeDeviceType,
        _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );


    NTSTATUS __stdcall InstanceQueryTeardown(
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );


    VOID __stdcall InstanceTeardownStart(
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );


    VOID __stdcall InstanceTeardownComplete(
        _In_ PCFLT_RELATED_OBJECTS FltObjects,
        _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );


    NTSTATUS __stdcall Unload(
        _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

}


// WE ADD CALLBACKS FOR THE 2 MAJOR FUNCTION CODES INVOLVED IN THE DELETION OF FILES
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE, 0, fsmon::PreCreate, nullptr},
    {IRP_MJ_SET_INFORMATION, 0, fsmon::PreSetInformation, nullptr},
    { IRP_MJ_OPERATION_END }
};


//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    fsmon::Unload,                           //  MiniFilterUnload

    fsmon::InstanceSetup,                    //  InstanceSetup
    fsmon::InstanceQueryTeardown,            //  InstanceQueryTeardown
    fsmon::InstanceTeardownStart,            //  InstanceTeardownStart
    fsmon::InstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};
