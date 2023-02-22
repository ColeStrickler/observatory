#pragma once
#include <ntifs.h>
#include <wdm.h>
#include <stdlib.h>
#include "KernelRaiiMgmt.h"
#include "providers.h"

// TYPEDEFS
typedef UINT32 DWORD;
typedef unsigned char BYTE;
#define DRIVER_TAG 'obsv'


// STRUCTURES
typedef struct Globals
{
	FastMutex					EventsMutex;
	LIST_ENTRY					EventsHead;
	int							EventCount;

	FastMutex					MonitoredFilesMutex;
	LIST_ENTRY					MonitoredFiles;
	int							MonitoredFilesCount;

}*PGlobals;

typedef struct MonitoredFile
{
	LIST_ENTRY Entry;
	UNICODE_STRING FilePath;
	ULONG PID;
}*PMonitoredFile;


// FUNCTIONS
void PushEvent(LIST_ENTRY* entry, LIST_ENTRY* ListHead, FastMutex& Mutex, int& count);
void PushMonitoredFile(LIST_ENTRY* entry, LIST_ENTRY* ListHead, int& count);
void PushMonitoredFile(LIST_ENTRY* entry, LIST_ENTRY* ListHead, FastMutex& Mutex, int& count);
void charToUnicodeString(char* text, UNICODE_STRING& outstring);



// EVENT INFRASTRUCTURE
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
	LIST_ENTRY Entry;
	T Data;
};

struct EventHeader
{
	EventType Type;
	DWORD Size;
	LARGE_INTEGER Timestamp;
};



struct FileEvent : EventHeader
{
	FileEventType Action;
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
	DWORD OffsetValue;
	DWORD ValueLength;
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



// DRIVER CONTROL CODES
#define DRIVER_IOCTL_CLEAR CTL_CODE(0x8000, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
;