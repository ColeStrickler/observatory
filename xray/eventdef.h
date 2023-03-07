#pragma once
#include <Windows.h>
#include "fileparser.h"
#include "LinkedList.h"
#include "kerneldef.h"


enum class EventType : short
{
	FileParse,
	FileEvent,
	NetworkEvent,
	ProcessEvent,
	ImageLoadEvent,
	ThreadEvent,
	RemoteThreadEvent,
	RegistryEvent,
	ObjectCallbackEvent,
};


enum class FileEventType : short
{
	Read,
	Write,
	Create,
	Delete
};


template<typename T>
struct Event
{
	lEntry Entry;
	T Data;
};

struct EventHeader
{
	EventType Type;
	DWORD Size;
	LARGE_INTEGER Timestamp;
};

struct FileParseEvent : EventHeader
{
	staticparse::ExtractInfo ParseInfo;
};

struct FileEvent : EventHeader
{ 
	FileEventType Action;
	DWORD Pid;
	DWORD OffsetPath;
	DWORD PathLength;
	DWORD OffsetProcess;
	DWORD ProcessLength;
};


struct NetworkEvent : EventHeader
{
	DWORD OffsetProcessName;
	DWORD ProcessNameLength;
	CHAR DstIp[16];
	int Port;
};

struct ProcessEvent : EventHeader
{
	DWORD Pid;
	DWORD ParentPid;
	DWORD OffsetImageFileName;
	DWORD ImageFileNameLength;
	DWORD OffsetParentName;
	DWORD ParentNameLength;
};

struct ImageLoadEvent : EventHeader
{
	DWORD Pid;
	DWORD OffsetProcessName;
	DWORD ProcessNameLength;
	uintptr_t ImageBase;
	DWORD OffsetImageName;
	DWORD ImageNameLength;
};

struct ThreadEvent : EventHeader
{
	DWORD Tid;
	DWORD Pid;
	DWORD OffsetProcessName;
	DWORD ProcessNameLength;
};

struct RemoteThreadEvent : ThreadEvent
{
	DWORD TargetProcessId;
	DWORD OffsetTargetProcessName;
	DWORD TargetProcessNameLength;
};

struct RegistryEvent : EventHeader
{
	REG_NOTIFY_CLASS Action;
	DWORD Pid;
	DWORD OffsetProcessName;
	DWORD ProcessNameLength;
	DWORD OffsetDataValue;
	DWORD DataLength;
	DWORD DataType;
	DWORD OffsetDataName;
	DWORD DataNameLength;
	DWORD OffsetRegistryPath;
	DWORD RegistryPathLength;
};


struct ObjectCallbackEvent : EventHeader
{
	DWORD HandlePid;
	DWORD Pid;
	DWORD OffsetProcessName;
	DWORD ProcessNameLength;
	DWORD OffsetHandleProcessName;
	DWORD HandleProcessNameLength;
};

