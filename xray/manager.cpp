#include "manager.h"




EventType eventparser::CheckType(PlEntry* Event)
{
	return *(EventType*)((UINT64)Event + sizeof(PlEntry));
}



json eventparser::ParseFileParseEvent(Event<FileParseEvent>* fileParseEvent)
{
	json retData;
	auto& data = fileParseEvent->Data;
	auto& pInfo = data.ParseInfo;

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
	retData["Timestamp"] = DisplayTime(data.Timestamp);
	retData["DataPath"] = std::string((char*)(fileEvent + data.OffsetPath), data.PathLength);
	retData["Process"] = std::string((char*)(fileEvent + data.OffsetProcess), data.ProcessLength);
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

	retData["Timestamp"] = DisplayTime(data.Timestamp);
	retData["ProcessId"] = data.Pid;
	retData["File"] = std::string((char*)(processEvent + data.OffsetImageFileName), data.ImageFileNameLength);
	retData["Parent ProcessId"] = data.ParentPid;
	retData["ParentProcess"] = std::string((char*)(processEvent + data.OffsetParentName), data.ParentNameLength);

	return retData;
}

json eventparser::ParseImageLoadEvent(Event<ImageLoadEvent>* imageLoadEvent)
{
	json retData;
	auto& data = imageLoadEvent->Data;

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

	retData["Timestamp"] = DisplayTime(data.Timestamp);
	retData["Operation"] = REG_NOTIFY_CLASS_MAPPINGS[data.Action];
	retData["Registry Path"] = std::string((char*)(registryEvent + data.OffsetRegistryPath), data.RegistryPathLength);
	
	if (data.ValueLength)
	{
		retData["Value"] = std::string((char*)(registryEvent + data.OffsetValue), data.ValueLength);
	}
	else {
		retData["Value"] = "N/A";
	}

	return retData;
}

json eventparser::ParseObjectCallbackEvent(Event<ObjectCallbackEvent>* objectCallbackEvent)
{
	json retData;
	auto& data = objectCallbackEvent->Data;

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
			auto evt = (Event<FileEvent>*)(pEvent);
			return eventparser::ParseFileEvent(evt);
		}

		case EventType::NetworkEvent:
		{
			auto evt = (Event<NetworkEvent>*)(pEvent);
			return eventparser::ParseNetworkEvent(evt);
		}

		case EventType::ProcessEvent:
		{
			auto evt = (Event<ProcessEvent>*)(pEvent);
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
			auto evt = (Event<RegistryEvent>*)(pEvent);
			return eventparser::ParseRegistryEvent(evt);
		}

		case EventType::ObjectCallbackEvent:
		{
			auto evt = (Event<ObjectCallbackEvent>*)(pEvent);
			return eventparser::ParseObjectCallbackEvent(evt);
		}

		case EventType::EndSequence:
		{
			
			// need to implement exit functionality here

			break;
		}

		default:
			return nullptr;
	}

}




manager::manager()
{
	InitializeListHeader(&EventHead);



}


void manager::ConsumeErrors(std::vector<DWORD>& ErrorVec)
{
		
	while (ErrorVec.size() > 0)
	{
		Errors.push_back(ErrorVec.back());
		ErrorVec.pop_back();
	}

	return;
}

