#include "manager.h"

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

HANDLE manager::GetFileHandle()
{
	return this->hFile;
}

BOOL manager::CheckExit()
{
	return this->exit;
}

std::string manager::GetApiEndpoint()
{
	std::string ret;
	ret += this->Server;
	ret += this->ServerApiEndpoint;
	return ret;
}


void API_sendThread(manager* mgr)
{
	while (true)
	{
		if (g_Struct.ReadEvents->EntryCount == 0)
		{
			Sleep(25);
			continue;
		}
		
		if (mgr->Server.size() == 0)
		{
			Sleep(25);
			continue;
		}

		PlEntry curr = nullptr;
		HANDLE& hMutex = g_Struct.ReadEventsMutex;
		if (hMutex != INVALID_HANDLE_VALUE)
		{
			RAII::MutexLock Lock(hMutex);
			curr = PopEntry(g_Struct.ReadEvents);
			PlEntry check = PopEntry(g_Struct.ReadEvents);
		}
		if (curr == nullptr)
		{
			continue;
		}

		json parsed = eventparser::EventToJson(&curr);
		printf(parsed.dump().c_str());
		printf("\n\n");

		Url endpoint = std::string("http://") + mgr->GetApiEndpoint();
		Response r = Post(endpoint, Body{ parsed.dump() }, Header{ {"Content-Type", "application/json"} });
		free(curr);
	}
}

void DriverEventConsumerThread(manager* mgr)
{
	while (true)
	{
		// TEST REMOVE LATER
		Sleep(1000);
		if (mgr->GetFileHandle() == INVALID_HANDLE_VALUE)
		{
			printf("invalid driver handle...\n");
			Sleep(25);
			continue;
		}

		BYTE read_buffer[1 << 16];
		DWORD bytes = 0;
		if (!ReadFile(mgr->GetFileHandle(), read_buffer, sizeof(read_buffer), &bytes, 0))
		{
			printf("DriverEventConsumerThread: Could not read from driver.\n");
			continue;
		}
		if (bytes != 0)
		{
			
			HANDLE& hMutex = g_Struct.ReadEventsMutex;
			auto count = bytes;
			BYTE* buf = read_buffer;

			while (count > 0)
			{
				auto header = (EventHeader*)buf;

				switch (header->Type)
				{
					case EventType::FileEvent:
					{
						auto fe = (FileEvent*)buf;
						size_t allocSize = sizeof(Event<FileEvent>) + (fe->Size - sizeof(FileEvent));
						auto evt = (Event<FileEvent>*)new BYTE[allocSize];
						memset(evt, 0x00, allocSize);
						memcpy(&evt->Data, buf, fe->Size);
						RAII::MutexLock Lock(hMutex);
						PushEntry(g_Struct.ReadEvents, &evt->Entry);
						break;
					}

					case EventType::NetworkEvent:
					{
						auto evt = new Event<NetworkEvent>();
						auto ne = (NetworkEvent*)buf;
						memcpy(&evt->Data, ne, sizeof(NetworkEvent));
						RAII::MutexLock Lock(hMutex);
						PushEntry(g_Struct.ReadEvents, &evt->Entry);
						break;
					}

					case EventType::ProcessEvent:					// this one is working
					{
						auto pe = (ProcessEvent*)buf;
						size_t allocSize = sizeof(Event<ProcessEvent>) + (pe->Size - sizeof(ProcessEvent));
						auto evt = (Event<ProcessEvent>*)new BYTE[allocSize];
						memset(evt, 0x00, allocSize);
						memcpy(&evt->Data, buf, pe->Size);
						RAII::MutexLock Lock(hMutex);
						PushEntry(g_Struct.ReadEvents, &evt->Entry);
						break;
					}

					case EventType::ImageLoadEvent:
					{
						auto evt = new Event<ImageLoadEvent>();
						auto ile = (ImageLoadEvent*)buf;
						memcpy(&evt->Data, ile, sizeof(ImageLoadEvent));
						RAII::MutexLock Lock(hMutex);
						PushEntry(g_Struct.ReadEvents, &evt->Entry);
						break;
					}

					case EventType::ThreadEvent:
					{
						auto evt = new Event<ThreadEvent>();
						auto te = (ThreadEvent*)buf;
						memcpy(&evt->Data, te, sizeof(ThreadEvent));
						RAII::MutexLock Lock(hMutex);
						PushEntry(g_Struct.ReadEvents, &evt->Entry);
						break;
					}

					case EventType::RemoteThreadEvent:
					{
						auto evt = new Event<RemoteThreadEvent>();
						auto rte = (RemoteThreadEvent*)buf;
						memcpy(&evt->Data, rte, sizeof(RemoteThreadEvent));
						RAII::MutexLock Lock(hMutex);
						PushEntry(g_Struct.ReadEvents, &evt->Entry);
						break;
					}

					case EventType::RegistryEvent:
					{
						auto re = (RegistryEvent*)buf;
						size_t allocSize = sizeof(Event<RegistryEvent>) + (re->Size - sizeof(RegistryEvent));
						auto evt = (Event<RegistryEvent>*)new BYTE[allocSize];
						memset(evt, 0x00, allocSize);
						memcpy(&evt->Data, buf, re->Size);
						RAII::MutexLock Lock(hMutex);
						PushEntry(g_Struct.ReadEvents, &evt->Entry);
						break;
					}

					case EventType::ObjectCallbackEvent:
					{
						auto evt = new Event<ObjectCallbackEvent>();
						auto oce = (ObjectCallbackEvent*)buf;
						memcpy(&evt->Data, oce, sizeof(ObjectCallbackEvent));
						RAII::MutexLock Lock(hMutex);
						PushEntry(g_Struct.ReadEvents, &evt->Entry);
						break;
					}

				default:
					break;

				}
				buf += header->Size;
				count -= header->Size;
			}
			//printf("Read no events..\n");
		}
	}
}

manager::manager(char* _Server) : Server(_Server), hFile(INVALID_HANDLE_VALUE), exit(FALSE), ServerApiEndpoint("/api")
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
		
	
	hFile = CreateFile(L"\\\\.\\observatorydriver", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Unable to obtain handle to driver.\n");
		exit = TRUE;
		return;
	}


	const char* file = "\\??\\C:\\Windows\\System32\\cmd.exe";
	//const char* file = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
	RAII::NewBuffer buf(strlen(file) + 1);
	BYTE* buffer = buf.Get();

	memcpy(buffer, file, strlen(file));


	DWORD retBytes;
	// This is temporary for testing
	WriteFile(hFile, buffer, strlen(file) + 1, &retBytes, 0);

	// Thread Initialization
	//hAPI_recvThread =				CreateThread(0, 0, (LPTHREAD_START_ROUTINE)API_recvThread, this, 0, 0);
	hAPI_sendThread =				CreateThread(0, 0, (LPTHREAD_START_ROUTINE)API_sendThread, this, 0, 0);
	hDriverEventConsumerThread =	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)DriverEventConsumerThread, this, 0, 0);

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

