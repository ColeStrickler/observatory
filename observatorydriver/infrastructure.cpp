#pragma once
#include "infrastructure.h"


void PushEvent(LIST_ENTRY* entry, LIST_ENTRY* ListHead, FastMutex& Mutex, int& count) {
	AutoLock<FastMutex> lock(Mutex);

	// too many items, remove oldest
	if (count > 1024) {
		auto head = RemoveHeadList(ListHead);
		count--;
		auto item = CONTAINING_RECORD(head, Event<EventHeader>, Entry);
		ExFreePool(item);
	}
	InsertTailList(ListHead, entry);
	count++;
}


void PushMonitoredFile(LIST_ENTRY* entry, LIST_ENTRY* ListHead, FastMutex& Mutex, int& count)
{
	AutoLock<FastMutex> lock(Mutex);

	// too many items, remove oldest
	if (count > 1024) {
		auto head = RemoveHeadList(ListHead);
		count--;
		auto item = CONTAINING_RECORD(head, MonitoredFile, Entry);
		ExFreePool(item);
	}
	auto item = CONTAINING_RECORD(entry, MonitoredFile, Entry);
	item->PID = item->PID;
	InsertTailList(ListHead, entry);
	count++;
}

void PushMonitoredFile(LIST_ENTRY* entry, LIST_ENTRY* ListHead, int& count)
{
	// too many items, remove oldest
	if (count > 1024) {
		auto head = RemoveHeadList(ListHead);
		count--;
		auto item = CONTAINING_RECORD(head, MonitoredFile, Entry);
		ExFreePool(item);
	}
	auto item = CONTAINING_RECORD(entry, MonitoredFile, Entry);
	item->PID = item->PID;
	InsertTailList(ListHead, entry);
	count++;
}


void charToUnicodeString(char* text, UNICODE_STRING& outstring)
{
	size_t size = (strlen(text) + 1) * sizeof(wchar_t);
	wchar_t* wText = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, size, DRIVER_TAG);
	memset(wText, 0, size);
	mbstowcs(wText, text, (strlen(text)));
	RtlInitUnicodeString(&outstring, wText);
	ExFreePool(wText);
}