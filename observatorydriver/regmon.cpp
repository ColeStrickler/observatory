#include "regmon.h"

extern Globals g_Struct;

NTSTATUS regmon::OnRegistryNotify(PVOID context, PVOID arg1, PVOID arg2)
{
	if (IsListEmpty(&g_Struct.MonitoredFiles))
	{
		return STATUS_SUCCESS;
	}

	UNREFERENCED_PARAMETER(context);
	NTSTATUS status = STATUS_SUCCESS;
	PCUNICODE_STRING KeyName = nullptr;
	REG_NOTIFY_CLASS op;
	PVOID Data = nullptr;
	DWORD DataSize = 0;


	auto pid = HandleToUlong(PsGetCurrentProcessId());
	if (!procmon::CheckIfMonitoredPID(g_Struct.MonitoredFiles.Flink, pid, g_Struct.MonitoredFilesMutex))
	{
		return STATUS_SUCCESS;
	}
	


	switch ((REG_NOTIFY_CLASS)(ULONG_PTR)arg1)
	{
		case RegNtPreSetValueKey:
		{
			KdPrint(("RegNtPreSetValueKey\n"));
			PEPROCESS proc;
			status = PsLookupProcessByProcessId(PsGetCurrentProcessId(), &proc);
			if (!NT_SUCCESS(status))
			{
				KdPrint(("failed to get PEPROCESS\n"));
			}
			PUNICODE_STRING ProcessName;
			if (!NT_SUCCESS(helpers::GetProcessImageName(proc, &ProcessName)))
			{
				KdPrint(("regmon::OnRegistryNotify() --> could not get process image name.\n"));
				return status;
			}

			op = REG_NOTIFY_CLASS::RegNtPreSetValueKey;
			auto args = static_cast<REG_SET_VALUE_KEY_INFORMATION*> (arg2);
			Data = args->Data;
			DataSize = args->DataSize;
			if (!NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_Struct.RegCookie, args->Object, nullptr, &KeyName, 0)))
			{
				KdPrint(("regmon::OnRegistryNotify() --> failed to get callback object\n"));
				return STATUS_SUCCESS;
			}
			
			ULONG allocSize = sizeof(Event<RegistryEvent>) + KeyName->Length + DataSize + ProcessName->Length + args->ValueName->Length;
			auto evt = (Event<RegistryEvent>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
			if (evt == nullptr)
			{
				KdPrint(("regmon::OnRegistryNotify() --> could not allocate pool.\n"));
				break;
			}
			BYTE* WritePtr = (BYTE*)evt + sizeof(Event<RegistryEvent>);
			auto& ctx = evt->Data;


			ctx.Type = EventType::RegistryEvent;
			KeQuerySystemTime(&ctx.Timestamp);
			ctx.Action = op;
			ctx.Pid = pid;
			ctx.Size = sizeof(RegistryEvent) + KeyName->Length + DataSize + ProcessName->Length + args->ValueName->Length;
			ctx.OffsetProcessName = sizeof(RegistryEvent);
			ctx.OffsetRegistryPath = sizeof(RegistryEvent) + ProcessName->Length;
			ctx.OffsetDataValue = sizeof(RegistryEvent) + ProcessName->Length + KeyName->Length;
			ctx.OffsetDataName = sizeof(RegistryEvent) + ProcessName->Length + KeyName->Length + DataSize;
			ctx.ProcessNameLength = ProcessName->Length;
			ctx.RegistryPathLength = KeyName->Length;
			ctx.DataLength = DataSize;
			ctx.DataNameLength = args->ValueName->Length;
			ctx.DataType = args->Type;
			
			
			memcpy(WritePtr, ProcessName->Buffer, ProcessName->Length);
			WritePtr += ProcessName->Length;
			memcpy(WritePtr, KeyName->Buffer, KeyName->Length);
			WritePtr += KeyName->Length;
			memcpy(WritePtr, Data, DataSize);
			WritePtr += DataSize;
			memcpy(WritePtr, args->ValueName, args->ValueName->Length);
			PushEvent(&evt->Entry, &g_Struct.EventsHead, g_Struct.EventsMutex, g_Struct.EventCount);
			KdPrint(("regmon::OnRegistryNotify() --> Pushed Entry!.\n"));
			break;
		}

		case RegNtPreDeleteValueKey:
		{
			KdPrint(("RegNtPreDeleteValueKey\n"));
			PEPROCESS proc;
			PsLookupProcessByProcessId(PsGetCurrentProcessId(), &proc);
			PUNICODE_STRING ProcessName;
			if (!NT_SUCCESS(helpers::GetProcessImageName(proc, &ProcessName)))
			{
				KdPrint(("regmon::OnRegistryNotify() --> could not get process image name.\n"));
				return status;
			}

			op = REG_NOTIFY_CLASS::RegNtPreDeleteValueKey;
			auto args = static_cast<REG_DELETE_VALUE_KEY_INFORMATION*>(arg2);
			
			if (!NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_Struct.RegCookie, args->Object, nullptr, &KeyName, 0)))
			{
				KdPrint(("regmon::OnRegistryNotify() --> failed to get callback object\n"));
				return STATUS_SUCCESS;
			}
			
			ULONG allocSize = sizeof(Event<RegistryEvent>) + KeyName->Length + ProcessName->Length + args->ValueName->Length;
			auto evt = (Event<RegistryEvent>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
			if (evt == nullptr)
			{
				KdPrint(("regmon::OnRegistryNotify() --> could not allocate pool.\n"));
				break;
			}
			BYTE* WritePtr = (BYTE*)evt + sizeof(Event<RegistryEvent>);
			auto& ctx = evt->Data;

			ctx.Type = EventType::RegistryEvent;
			KeQuerySystemTime(&ctx.Timestamp);
			ctx.Action = op;
			ctx.Pid = pid;
			ctx.Size = sizeof(RegistryEvent) + KeyName->Length + ProcessName->Length + args->ValueName->Length;
			ctx.OffsetProcessName = sizeof(RegistryEvent);
			ctx.OffsetRegistryPath = sizeof(RegistryEvent) + ProcessName->Length;
			ctx.OffsetDataValue = sizeof(RegistryEvent) + ProcessName->Length + KeyName->Length;
			ctx.OffsetDataName = 0;
			ctx.ProcessNameLength = ProcessName->Length;
			ctx.RegistryPathLength = KeyName->Length;
			ctx.DataLength = 0;
			ctx.DataNameLength = args->ValueName->Length;
			ctx.DataType = 0;
			

			memcpy(WritePtr, ProcessName->Buffer, ProcessName->Length);
			WritePtr += ProcessName->Length;
			memcpy(WritePtr, KeyName->Buffer, KeyName->Length);
			WritePtr += KeyName->Length;
			memcpy(WritePtr, args->ValueName->Buffer, args->ValueName->Length);
			PushEvent(&evt->Entry, &g_Struct.EventsHead, g_Struct.EventsMutex, g_Struct.EventCount);
			KdPrint(("regmon::OnRegistryNotify() --> Pushed Entry!.\n"));
			break;
		}

		case RegNtPreDeleteKey:
		{
			KdPrint(("RegNtPreDeleteKey\n"));
			PEPROCESS proc;
			PsLookupProcessByProcessId(PsGetCurrentProcessId(), &proc);
			PUNICODE_STRING ProcessName;
			if (!NT_SUCCESS(helpers::GetProcessImageName(proc, &ProcessName)))
			{
				KdPrint(("regmon::OnRegistryNotify() --> could not get process image name.\n"));
				return status;
			}

			op = REG_NOTIFY_CLASS::RegNtPreDeleteKey;
			auto args = static_cast<REG_DELETE_KEY_INFORMATION*>(arg2);
			
			if (!NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_Struct.RegCookie, args->Object, nullptr, &KeyName, 0)))
			{
				KdPrint(("regmon::OnRegistryNotify() --> failed to get callback object\n"));
				return STATUS_SUCCESS;
			}
			KdPrint(("got callback key\n"));
			ULONG allocSize = sizeof(Event<RegistryEvent>) + KeyName->Length + ProcessName->Length;
			auto evt = (Event<RegistryEvent>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
			if (evt == nullptr)
			{
				KdPrint(("regmon::OnRegistryNotify() --> could not allocate pool.\n"));
				break;
			}
			KdPrint(("Alloc pool!\n"));
			BYTE* WritePtr = (BYTE*)evt + sizeof(Event<RegistryEvent>);
			auto& ctx = evt->Data;

			ctx.Type = EventType::RegistryEvent;
			KeQuerySystemTime(&ctx.Timestamp);
			ctx.Action = op;
			ctx.Pid = pid;
			ctx.Size = sizeof(RegistryEvent) + KeyName->Length + ProcessName->Length;
			ctx.OffsetProcessName = sizeof(RegistryEvent);
			ctx.OffsetRegistryPath = sizeof(RegistryEvent) + ProcessName->Length;
			ctx.OffsetDataValue = 0;
			ctx.OffsetDataName = 0;
			ctx.ProcessNameLength = ProcessName->Length;
			ctx.RegistryPathLength = KeyName->Length;
			ctx.DataLength = 0;
			ctx.DataNameLength = 0;
			ctx.DataType = 0;


			memcpy(WritePtr, ProcessName->Buffer, ProcessName->Length);
			WritePtr += ProcessName->Length;
			memcpy(WritePtr, KeyName->Buffer, KeyName->Length);
			PushEvent(&evt->Entry, &g_Struct.EventsHead, g_Struct.EventsMutex, g_Struct.EventCount);
			KdPrint(("regmon::OnRegistryNotify() --> Pushed Entry!.\n"));
			break;
		}

		case RegNtPreSetInformationKey:
		{
			KdPrint(("RegNtPreSetInformationKey\n"));
			PEPROCESS proc;
			PsLookupProcessByProcessId(PsGetCurrentProcessId(), &proc);
			PUNICODE_STRING ProcessName;
			if (!NT_SUCCESS(helpers::GetProcessImageName(proc, &ProcessName)))
			{
				KdPrint(("regmon::OnRegistryNotify() --> could not get process image name.\n"));
				return status;
			}

			op = REG_NOTIFY_CLASS::RegNtPreSetInformationKey;
			auto args = static_cast<REG_SET_INFORMATION_KEY_INFORMATION*>(arg2);
			Data = args->KeySetInformation;
			DataSize = args->KeySetInformationLength;
			if (!NT_SUCCESS(CmCallbackGetKeyObjectIDEx(&g_Struct.RegCookie, args->Object, nullptr, &KeyName, 0)))
			{
				KdPrint(("regmon::OnRegistryNotify() --> failed to get callback object\n"));
				return STATUS_SUCCESS;
			}

			ULONG allocSize = sizeof(Event<RegistryEvent>) + KeyName->Length + DataSize + ProcessName->Length + args->KeySetInformationLength;
			auto evt = (Event<RegistryEvent>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
			if (evt == nullptr)
			{
				KdPrint(("regmon::OnRegistryNotify() --> could not allocate pool.\n"));
				break;
			}
			BYTE* WritePtr = (BYTE*)evt + sizeof(Event<RegistryEvent>);
			auto& ctx = evt->Data;


			ctx.Type = EventType::RegistryEvent;
			KeQuerySystemTime(&ctx.Timestamp);
			ctx.Action = op;
			ctx.Pid = pid;
			ctx.Size = sizeof(RegistryEvent) + KeyName->Length + DataSize + ProcessName->Length + args->KeySetInformationLength;
			ctx.OffsetProcessName = sizeof(RegistryEvent);
			ctx.OffsetRegistryPath = sizeof(RegistryEvent) + ProcessName->Length;
			ctx.OffsetDataValue = sizeof(RegistryEvent) + ProcessName->Length + KeyName->Length;
			ctx.OffsetDataName = sizeof(RegistryEvent) + ProcessName->Length + KeyName->Length + DataSize;
			ctx.ProcessNameLength = ProcessName->Length;
			ctx.RegistryPathLength = KeyName->Length;
			ctx.DataLength = DataSize;
			ctx.DataNameLength = args->KeySetInformationLength;
			ctx.DataType = args->KeySetInformationClass;
			


			memcpy(WritePtr, ProcessName->Buffer, ProcessName->Length);
			WritePtr += ProcessName->Length;
			memcpy(WritePtr, KeyName->Buffer, KeyName->Length);
			WritePtr += KeyName->Length;
			memcpy(WritePtr, Data, DataSize);
			WritePtr += DataSize;
			memcpy(WritePtr, args->KeySetInformation, args->KeySetInformationLength);
			PushEvent(&evt->Entry, &g_Struct.EventsHead, g_Struct.EventsMutex, g_Struct.EventCount);
			KdPrint(("regmon::OnRegistryNotify() --> Pushed Entry!.\n"));
			break;
		}

		case RegNtPreCreateKey:
		{
			KdPrint(("RegNtPreCreateKey\n"));
			PEPROCESS proc;
			PsLookupProcessByProcessId(PsGetCurrentProcessId(), &proc);
			PUNICODE_STRING ProcessName;
			if (!NT_SUCCESS(helpers::GetProcessImageName(proc, &ProcessName)))
			{
				KdPrint(("regmon::OnRegistryNotify() --> could not get process image name.\n"));
				return status;
			}

			op = REG_NOTIFY_CLASS::RegNtPreCreateKey;
			auto args = static_cast<REG_PRE_CREATE_KEY_INFORMATION*>(arg2);
			Data = args->CompleteName->Buffer;
			DataSize = args->CompleteName->Length;


			ULONG allocSize = sizeof(Event<RegistryEvent>) + DataSize + ProcessName->Length;
			auto evt = (Event<RegistryEvent>*)ExAllocatePoolWithTag(NonPagedPool, allocSize, DRIVER_TAG);
			if (evt == nullptr)
			{
				KdPrint(("regmon::OnRegistryNotify() --> could not allocate pool.\n"));
				break;
			}
			BYTE* WritePtr = (BYTE*)evt + sizeof(Event<RegistryEvent>);
			auto& ctx = evt->Data;


			ctx.Type = EventType::RegistryEvent;
			KeQuerySystemTime(&ctx.Timestamp);
			ctx.Action = op;
			ctx.Pid = pid;
			ctx.Size = sizeof(RegistryEvent) + DataSize + ProcessName->Length;
			ctx.OffsetProcessName = sizeof(RegistryEvent);
			ctx.OffsetRegistryPath = sizeof(RegistryEvent) + ProcessName->Length;
			ctx.OffsetDataValue = 0;
			ctx.OffsetDataName = 0;
			ctx.ProcessNameLength = ProcessName->Length;
			ctx.RegistryPathLength = DataSize;
			ctx.DataLength = 0;
			ctx.DataNameLength = 0;
			ctx.DataType = 0;


			memcpy(WritePtr, ProcessName->Buffer, ProcessName->Length);
			WritePtr += ProcessName->Length;
			memcpy(WritePtr, Data, DataSize);
			PushEvent(&evt->Entry, &g_Struct.EventsHead, g_Struct.EventsMutex, g_Struct.EventCount);
			KdPrint(("regmon::OnRegistryNotify() --> Pushed Entry!.\n"));
			break;
		}
		default:
			break;
	}

	
	
	if (KeyName)
	{
		CmCallbackReleaseKeyObjectIDEx(KeyName);
	}
	return status;
}
