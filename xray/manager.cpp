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

		default:
			return nullptr;
	}

}



void CommandHandler(CommandHandler_Info* _CommandHandlerInfo)
{
	json CommandJson = json::parse((char*)_CommandHandlerInfo->commBuf);
	std::string Command = CommandJson["Command"];
	if (Command.size())
	{
		if (!_strcmpi(Command.c_str(), "start"))					// Start Analysis
		{
			std::string FileName = CommandJson["File"];
			if (FileName.size())								// Ensure we were given a filename
			{

				int send_check = send(_CommandHandlerInfo->connection_sock_fd, api_OK.dump().c_str(), strlen(api_OK.dump().c_str()), 0);
				if (send_check == -1)
				{
					printf("OK! to server failed.\n");
					return;
				}
				_CommandHandlerInfo->mgr->MonitoredFilePath = FileName;


				CHAR desktop_path[MAX_PATH + 1];
				if (SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop_path))
				{
					printf("Unable to get desktop.\n");
					send(_CommandHandlerInfo->connection_sock_fd, api_ERROR.dump().c_str(), strlen(api_ERROR.dump().data()), 0);
					return;
				}
				std::string Desktop(desktop_path);
				Desktop += "\\";
				Desktop += FileName;


				HANDLE hFile = INVALID_HANDLE_VALUE;
				hFile = CreateFileA(Desktop.c_str(), FILE_ALL_ACCESS, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
				if (hFile == INVALID_HANDLE_VALUE)
				{
					printf("Unable to write file to desktop.\n");
					send(_CommandHandlerInfo->connection_sock_fd, api_ERROR.dump().c_str(), strlen(api_ERROR.dump().data()), 0);
					return;
				}
				CloseHandle(hFile);



				hFile = CreateFileA(Desktop.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
				if (hFile == INVALID_HANDLE_VALUE)
				{
					printf("Unable to open append handle to file.\n");
					send(_CommandHandlerInfo->connection_sock_fd, api_ERROR.dump().c_str(), strlen(api_ERROR.dump().data()), 0);
					return;
				}

				int ret_bytes = 0;
				DWORD written;
				RAII::NewBuffer raii_buf(0x1000);
				BYTE* buf = raii_buf.Get();

				while (TRUE)
				{
					ret_bytes = recv(_CommandHandlerInfo->connection_sock_fd, (char*)buf, 0x1000, 0);
					if (ret_bytes == 0)
					{
						break;
					}


					if (!WriteFile(hFile, buf, ret_bytes, &written, 0))
					{
						printf("Error writing to file.\n");
						send(_CommandHandlerInfo->connection_sock_fd, api_ERROR.dump().c_str(), strlen(api_ERROR.dump().data()), 0);
						CloseHandle(hFile);
						return;

					}
					memset(buf, 0x00, 0x1000);
				}
				printf("Wrote file to %s\n", Desktop.c_str());
				CloseHandle(hFile);
				return;
			}
			else {
				printf("No filename found in 'start' command\n");
				send(_CommandHandlerInfo->connection_sock_fd, api_ERROR.dump().c_str(), strlen(api_ERROR.dump().data()), 0);
				return;
			}
		}
		else if (!_strcmpi(Command.c_str(), "stop"))
		{
			_CommandHandlerInfo->mgr->Stop();
			return;
		}


	}
	else {
		send(_CommandHandlerInfo->connection_sock_fd, api_ERROR.dump().c_str(), strlen(api_ERROR.dump().data()), 0);
		return;
	}


}


void API_recvThread(manager* mgr)
{
	addrinfo* ServerAddrInfo;
	addrinfo* ServerCopy;
	addrinfo setup;
	int server_sock_fd = 0;
	int conn_sock_fd = 0;


	memset(&setup, 0x00, sizeof(addrinfo));
	setup.ai_family = AF_INET;
	setup.ai_socktype = SOCK_STREAM;
	setup.ai_flags = AI_PASSIVE;

	printf("Using server: %s\n", mgr->Server.c_str());
	if (getaddrinfo(NULL, "9000", &setup, &ServerAddrInfo) != 0) {
		printf("Error %d\n", GetLastError());
		mgr->Errors.push_back(ERROR_GET_ADDRINFO);
		return;
	}

	ServerCopy = ServerAddrInfo;
	while (ServerCopy != nullptr)
	{
		int bind_success = -1;
		do {
			server_sock_fd = socket(ServerCopy->ai_family, ServerCopy->ai_socktype, ServerCopy->ai_protocol);
			if (server_sock_fd == -1)
			{
				mgr->Errors.push_back(ERROR_SOCKET_SET);
				break;
			}
			
			int opt = 1;
			if (setsockopt(server_sock_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(int)) == -1)
			{
				mgr->Errors.push_back(ERROR_SOCKET_SET);
				break;
			}

			bind_success = bind(server_sock_fd, ServerCopy->ai_addr, ServerCopy->ai_addrlen);
			if (bind_success == -1)
			{
				closesocket(server_sock_fd);
				break;
			}

		} while (FALSE);

		if (bind_success == 0)
		{
			printf("Bind success!\n");
			break;
		}
		ServerCopy = ServerCopy->ai_next;
	}

	if (ServerCopy == nullptr)
	{
		mgr->Errors.push_back(ERROR_SOCKET_NOBIND);
		printf("Socket Bind() failure!\n");
		return;
	}

	if (listen(server_sock_fd, 10) == -1)
	{
		mgr->Errors.push_back(ERROR_SOCKET_LISTEN);
		printf("listen() failure!\n");
	}

	struct sockaddr_storage conn_addr;              // We will store new connection addresses here;
	int size_conn_storage = sizeof(conn_addr);
	printf("Listening for new connections on port 9000...\n");
	while (TRUE)
	{
		conn_sock_fd = accept(server_sock_fd, (sockaddr*)&conn_addr, &size_conn_storage);
		if (conn_sock_fd == -1)
		{
			printf("error accept()\n");
			mgr->Errors.push_back(ERROR_SOCKET_ACCEPT);
			continue;
		}
		
		CHAR buf[0x1000];
		int ret_bytes = 0;
		int total_received = 0;

		while (TRUE)
		{
			ret_bytes = recv(conn_sock_fd, buf + total_received, 0x1000 - total_received, 0);
			total_received += ret_bytes;
			if (ret_bytes)
			{
				break;
			}
		}
		printf("Received: %d\n", total_received);

		if (total_received == 0)
		{
			continue;
		}

		BYTE* commBuf = new BYTE[total_received + 2];
		memset(commBuf, 0x00, total_received + 2);
		CommandHandler_Info comm;
		comm.commBuf = commBuf;
		comm.connection_sock_fd = conn_sock_fd;
		comm.mgr = mgr;
		
		
		memcpy(commBuf, buf, total_received);
		printf("%s", commBuf);
		Sleep(100);
		// This setup allows us to recover if we get a JSON parsing error
		// And also allows for handling one command at a time
		HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)CommandHandler, &comm, 0, 0);
		DWORD res = WaitForSingleObject(hThread, -1);
		if (res == WAIT_FAILED)
		{
			mgr->Errors.push_back(ERROR_COMMAND_HANDLER);
			printf("Error Command Handler!\n");
		}


		send(conn_sock_fd, api_ERROR.dump().c_str(), strlen(api_ERROR.dump().data()), 0);
		closesocket(conn_sock_fd);
		free(commBuf);
	}

}


void manager::Stop()
{
	this->exit = TRUE;
	return;
}

BOOL manager::CheckExit()
{
	return this->exit;
}


void API_sendThread(manager* mgr)
{

}

void DriverEventConsumerThread(manager* mgr)
{

}

manager::manager(char* _Server) : Server(_Server)
{
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData;
	int err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0) {
		/* Tell the user that we could not find a usable */
		/* Winsock DLL.                                  */
		printf("WSAStartup failed with error: %d\n", err);
		exit = TRUE;
		return;
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		/* Tell the user that we could not find a usable */
		/* WinSock DLL.                                  */
		printf("Could not find a usable version of Winsock.dll\n");
		WSACleanup();
		exit = TRUE;
		return;
	}
	else
	{
		printf("The Winsock 2.2 dll was found okay\n");
	}
		


	hAPI_recvThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)API_recvThread, this, 0, 0);
	hAPI_sendThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)API_sendThread, this, 0, 0);

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

