#include "eventparser.h"




EventType eventparser::CheckType(PlEntry* event)
{
	auto item = CONTAINING_RECORD(*event, Event<EventHeader>, Entry);
	return item->Data.Type;
}



json eventparser::ParseFileParseEvent(Event<FileParseEvent>* fileParseEvent)
{
	json retData;
	auto& data = fileParseEvent->Data;
	auto& pInfo = data.ParseInfo;

	retData["Type"] = "FileParseEvent";
	retData["File"] = pInfo.FileName;
	retData["File Size"] = pInfo.FileSize;
	retData["MD5"] = pInfo.HashInfo.MD5;
	retData["SHA-1"] = pInfo.HashInfo.SHA1;
	retData["SHA-256"] = pInfo.HashInfo.SHA256;

	for (auto& err : pInfo.Errors)
	{
		retData["Errors"].push_back(err);
	}

	for (auto& section : pInfo.Sections)
	{
		retData["Sections"].push_back({ section.SectionName, section.SizeOfRawData, section.HashInfo.MD5, section.HashInfo.SHA1, section.HashInfo.SHA256 });
	}

	for (const auto& lib : pInfo.Imports)		// Get all entries in the import map
	{
		for (const auto& func : lib.second)
		{
			retData["Imports"][lib.first].push_back(func);
		}
	}

	for (auto& s : pInfo.Strings)
	{
		bool insert = true;
		if (s.size() >= 4)
		{
			for (auto& c : s)
			{
				if (c < 0x20 || c > 0x7E)
				{
					insert = false;
					break;
				}
			}
			if (insert)
			{
				retData["Strings"].push_back(s);
			}

		}
	}


	if (pInfo.x86)
	{
		retData["Architecture"] = "32bit";
	}
	else {
		retData["Architecture"] = "64bit";
	}

	return retData;
}


json eventparser::ParseFileEvent(Event<FileEvent>* fileEvent)
{
	json retData;
	auto& data = fileEvent->Data;


	std::wstring wPath = std::wstring((wchar_t*)((uintptr_t)&fileEvent->Data + data.OffsetPath), data.PathLength / 2);
	std::wstring wProc = std::wstring((wchar_t*)((uintptr_t)&fileEvent->Data + data.OffsetProcess), data.ProcessLength / 2);
	std::string Path = WstringToString(wPath);
	std::string Proc = WstringToString(wProc);
	

	retData["Type"] = "ParseFileEvent";
	retData["Timestamp"] = DisplayTime(data.Timestamp);
	retData["DataPath"] = Path;
	retData["Process"] = Proc;
	retData["ProcessId"] = data.Pid;
	switch (data.Action)
	{
	case FileEventType::Read:
	{
		retData["Action"] = "Read";
		break;
	}

	case FileEventType::Write:
	{
		retData["Action"] = "Write";
		break;
	}

	case FileEventType::Create:
	{
		retData["Action"] = "Create";
		break;
	}

	case FileEventType::Delete:
	{
		retData["Action"] = "Delete";
		break;
	}

	default:
		retData["Action"] = "N/A";
		break;
	}

	return retData;
}


json eventparser::ParseNetworkEvent(Event<NetworkEvent>* networkEvent)
{
	json retData;
	auto& data = networkEvent->Data;

	retData["Type"] = "ParseNetworkEvent";
	retData["Timestamp"] = DisplayTime(data.Timestamp);
	retData["Destination Ip"] = std::string(data.DstIp, 16);
	retData["Port"] = data.Port;
	retData["Process"] = std::string((char*)(networkEvent + data.OffsetProcessName), data.ProcessNameLength);

	return retData;
}


json eventparser::ParseProcessEvent(Event<ProcessEvent>* processEvent)
{
	json retData;
	auto& data = processEvent->Data;


	std::wstring file = std::wstring((wchar_t*)((uintptr_t)&processEvent->Data + data.OffsetImageFileName), data.ImageFileNameLength / 2);
	std::string file_formatted = WstringToString(file);
	std::wstring parent_proc = std::wstring((wchar_t*)((uintptr_t)&processEvent->Data + data.OffsetParentName), data.ParentNameLength / 2);
	std::string parent_proc_formatted = WstringToString(parent_proc);
	retData["Type"] = "ParseProcessEvent";
	retData["Timestamp"] = DisplayTime(data.Timestamp);
	retData["ProcessId"] = data.Pid;
	retData["File"] = file_formatted;
	retData["Parent ProcessId"] = data.ParentPid;
	retData["ParentProcess"] = parent_proc_formatted;

	return retData;
}

json eventparser::ParseImageLoadEvent(Event<ImageLoadEvent>* imageLoadEvent)
{
	json retData;
	auto& data = imageLoadEvent->Data;

	retData["Type"] = "ParseImageLoadEvent";
	retData["Timestamp"] = DisplayTime(data.Timestamp);
	retData["Load Base"] = data.ImageBase;
	retData["Process"] = std::string((char*)(imageLoadEvent + data.OffsetProcessName), data.ProcessNameLength);
	retData["Load Image"] = std::string((char*)(imageLoadEvent + data.OffsetImageName), data.ImageNameLength);
	retData["ProcessId"] = data.Pid;

	return retData;
}

json eventparser::ParseThreadEvent(Event<ThreadEvent>* threadEvent)
{
	json retData;
	auto& data = threadEvent->Data;

	retData["Type"] = "ParseThreadEvent";
	retData["Timestamp"] = DisplayTime(data.Timestamp);
	retData["ThreadId"] = data.Tid;
	retData["Process"] = std::string((char*)(threadEvent + data.OffsetProcessName), data.ProcessNameLength);
	retData["ProcessId"] = data.Pid;

	return retData;
}

json eventparser::ParseRemoteThreadEvent(Event<RemoteThreadEvent>* remoteThreadEvent)
{
	json retData;
	auto& data = remoteThreadEvent->Data;

	retData["Type"] = "ParseRemoteThreadEvent";
	retData["Timestamp"] = DisplayTime(data.Timestamp);
	retData["ThreadId"] = data.Tid;
	retData["Creator Process"] = std::string((char*)(remoteThreadEvent + data.OffsetProcessName), data.ProcessNameLength);
	retData["Target Process"] = std::string((char*)(remoteThreadEvent + data.OffsetTargetProcessName), data.TargetProcessNameLength);
	retData["ProcessId"] = data.Pid;
	retData["Target ProcessId"] = data.TargetProcessId;

	return retData;
}

json eventparser::ParseRegistryEvent(Event<RegistryEvent>* registryEvent)
{
	json retData;
	auto& data = registryEvent->Data;

	retData["Type"] = "ParseRegistryEvent";
	retData["Timestamp"] = DisplayTime(data.Timestamp);
	std::wstring wProcess = std::wstring((wchar_t*)((uintptr_t)&registryEvent->Data + data.OffsetProcessName), data.ProcessNameLength / 2);

	std::string Process = WstringToString(wProcess);


	retData["ProcessId"] = data.Pid;
	retData["Process"] = Process;
	

	switch (data.Action)
	{
		case RegNtPreCreateKey:
		{
			retData["Action"] = "CreateKey";
			std::wstring wKeyName = std::wstring((wchar_t*)((uintptr_t)&registryEvent->Data + data.OffsetRegistryPath), data.RegistryPathLength / 2); // no divide by two because it isnt from a UNICODE_STRING
			std::string KeyName = WstringToString(wKeyName);
			retData["RegistryKey"] = KeyName;
			break;
		}

		case RegNtPreSetInformationKey:
		{
			retData["Action"] = "SetInformationKey";
			std::wstring wKeyName = std::wstring((wchar_t*)((uintptr_t)&registryEvent->Data + data.OffsetRegistryPath), data.RegistryPathLength / 2);
			std::string KeyName = WstringToString(wKeyName);
			retData["RegistryKey"] = KeyName;


			switch (*(DWORD*)((uintptr_t)&registryEvent->Data + data.OffsetDataValue))
			{
				case 0:
				{
					retData["KeySetInformationClass"] = "KeyWriteTimeInformation";
					break;
				}

				case 1:
				{
					retData["KeySetInformationClass"] = "KeyWow64FlagsInformation";
				}

				case 2:
				{
					retData["KeySetInformationClass"] = "KeyControlFlagsInformation";
				}

				case 3:
				{
					retData["KeySetInformationClass"] = "KeySetVirtualizationInformation";
				}

				case 4:
				{
					retData["KeySetInformationClass"] = "KeySetDebugInformation";
				}

				case 5:
				{
					retData["KeySetInformationClass"] = "KeySetHandleTagsInformation";
				}

				case 6:
				{
					retData["KeySetInformationClass"] = "KeySetLayerInformation";
				}

				case 7:
				{
					retData["KeySetInformationClass"] = "KeySetInfoClass";
				}
				
				default:
					retData["KeySetInformationClass"] = "N/A";
				
			}
			
		}

		case RegNtPreDeleteKey:
		{
			retData["Action"] = "DeleteKey";

			std::wstring wKeyName = std::wstring(((wchar_t*)(uintptr_t)&registryEvent->Data + data.OffsetRegistryPath), data.RegistryPathLength / 2);
			std::string KeyName = WstringToString(wKeyName);
			retData["RegistryKey"] = KeyName;
			break;
		}

		case RegNtPreDeleteValueKey:
		{
			retData["Action"] = "DeleteValueKey";
			std::wstring wKeyName = std::wstring(((wchar_t*)(uintptr_t)&registryEvent->Data + data.OffsetRegistryPath), data.RegistryPathLength / 2);
			std::string KeyName = WstringToString(wKeyName);
			retData["RegistryKey"] = KeyName;
			std::wstring wValName = std::wstring(((wchar_t*)(uintptr_t)&registryEvent->Data + data.OffsetDataName), data.DataNameLength / 2);
			std::string ValName = WstringToString(wValName);
			retData["ValueName"] = ValName;
			break;
		}

		case RegNtPreSetValueKey:
		{
			retData["Action"] = "SetValueKey";
			std::wstring wKeyName = std::wstring((wchar_t*)((uintptr_t)&registryEvent->Data + data.OffsetRegistryPath), data.RegistryPathLength / 2);
			std::string KeyName = WstringToString(wKeyName);
			retData["RegistryKey"] = KeyName;
			std::wstring wValName = std::wstring((wchar_t*)((uintptr_t)&registryEvent->Data + data.OffsetDataName), data.DataNameLength / 2);
			std::string ValName = WstringToString(wValName);
			retData["ValueName"] = ValName;


			switch (data.DataType)
			{

				case REG_SZ:
				{
					std::wstring wData = std::wstring(((wchar_t*)(uintptr_t)&registryEvent->Data + data.OffsetDataName), data.DataLength / 2);
					std::string data = WstringToString(wData);
					retData["Data"] = data;
					break;
				}

				case REG_MULTI_SZ:
				{

					std::wstring wData = std::wstring(((wchar_t*)(uintptr_t)&registryEvent->Data + data.OffsetDataName), data.DataLength / 2);
					std::string data = WstringToString(wData);
					retData["Data"] = data;
					break;
				}

				default:
				{
					retData["Data"] = BinaryToString((void*)((uintptr_t)&registryEvent->Data + data.OffsetDataName), data.DataLength);
					break;
				}
			}
		}

		default:
			break;
	}

	return retData;
}

json eventparser::ParseObjectCallbackEvent(Event<ObjectCallbackEvent>* objectCallbackEvent)
{
	json retData;
	auto& data = objectCallbackEvent->Data;

	retData["Type"] = "ParseObjectCallbackEvent";
	retData["Timestamp"] = DisplayTime(data.Timestamp);
	retData["Process"] = std::string((char*)(objectCallbackEvent + data.OffsetProcessName), data.ProcessNameLength);
	retData["Handle ProcessId"] = data.Pid;
	retData["ProcessId"] = data.HandlePid;
	retData["Handle Process"] = std::string((char*)(objectCallbackEvent + data.OffsetHandleProcessName), data.HandleProcessNameLength);

	return retData;
}

json eventparser::EventToJson(PlEntry* pEvent)
{
	EventType type = CheckType(pEvent);

	switch (type)
	{
	case EventType::FileParse:
	{
		auto evt = (Event<FileParseEvent>*)(pEvent);
		return eventparser::ParseFileParseEvent(evt);
	}

	case EventType::FileEvent:
	{
		auto evt = CONTAINING_RECORD(*pEvent, Event<FileEvent>, Entry);
		return eventparser::ParseFileEvent(evt);
	}

	case EventType::NetworkEvent:
	{
		auto evt = (Event<NetworkEvent>*)(pEvent);
		return eventparser::ParseNetworkEvent(evt);
	}

	case EventType::ProcessEvent:
	{
		auto evt = CONTAINING_RECORD(*pEvent, Event<ProcessEvent>, Entry);
		return eventparser::ParseProcessEvent(evt);
	}

	case EventType::ImageLoadEvent:
	{
		auto evt = (Event<ImageLoadEvent>*)(pEvent);
		return eventparser::ParseImageLoadEvent(evt);
	}

	case EventType::ThreadEvent:
	{
		auto evt = (Event<ThreadEvent>*)(pEvent);
		return eventparser::ParseThreadEvent(evt);
	}

	case EventType::RemoteThreadEvent:
	{
		auto evt = (Event<RemoteThreadEvent>*)(pEvent);
		return eventparser::ParseRemoteThreadEvent(evt);
	}

	case EventType::RegistryEvent:
	{
		auto evt = CONTAINING_RECORD(*pEvent, Event<RegistryEvent>, Entry);
		return eventparser::ParseRegistryEvent(evt);
	}

	case EventType::ObjectCallbackEvent:
	{
		auto evt = (Event<ObjectCallbackEvent>*)(pEvent);
		return eventparser::ParseObjectCallbackEvent(evt);
	}

	default:
		return nullptr;
	}

}
