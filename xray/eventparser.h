#pragma once
#include "manager.h"
#include <iostream>

using namespace nlohmann;




namespace eventparser
{
	EventType CheckType(PlEntry* Event);
	json EventToJson(PlEntry* Event);							// We will take in the first elment of an Event struct template and parse it from here
	json ParseFileParseEvent(Event<FileParseEvent>* fileEvent);
	json ParseFileEvent(Event<FileEvent>* fileEvent);
	json ParseNetworkEvent(Event<NetworkEvent>* networkEvent);
	json ParseProcessEvent(Event<ProcessEvent>* processEvent);
	json ParseImageLoadEvent(Event<ImageLoadEvent>* imageLoadEvent);
	json ParseThreadEvent(Event<ThreadEvent>* threadEvent);
	json ParseRemoteThreadEvent(Event<RemoteThreadEvent>* remoteThreadEvent);
	json ParseRegistryEvent(Event<RegistryEvent>* registryEvent);
	json ParseObjectCallbackEvent(Event<ObjectCallbackEvent>* objectCallbackEvent);
};


