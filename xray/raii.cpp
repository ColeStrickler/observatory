#include "raii.h"

RAII::Handle::Handle(HANDLE hHandle)
{
    _hHandle = hHandle;
}

void RAII::Handle::Update(HANDLE hHandle)
{
    _hHandle = hHandle;
}
HANDLE RAII::Handle::Get()
{
    return _hHandle;
}

BOOL RAII::Handle::Empty()
{
    if (_hHandle == NULL)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

BOOL RAII::Handle::Close()
{
    if (CloseHandle(_hHandle))
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}
RAII::Handle::~Handle()
{
    if (_hHandle) CloseHandle(_hHandle);
}



RAII::HeapBuffer::HeapBuffer(size_t size) {
    buf = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

BYTE* RAII::HeapBuffer::Get() {
    return buf;
}
RAII::HeapBuffer::~HeapBuffer() {
    if (buf != nullptr) {
        HeapFree(GetProcessHeap(), NULL, buf);
    }
}

RAII::NewBuffer::NewBuffer(size_t size) {
    buf = new BYTE[size]{ 0x00 };
    memset(buf, 0x00, size);
}


RAII::NewBuffer::NewBuffer(BYTE* buffer) {
    buf = buffer;
}

RAII::NewBuffer::~NewBuffer() {
    delete buf;
}

BYTE* RAII::NewBuffer::Get() {
    return buf;
}


// USER MODE MUTEX RAII WRAPPER
RAII::MutexLock::MutexLock(HANDLE& hMutex) : _hMutex(hMutex)
{
    DWORD res;
    res = WaitForSingleObject(_hMutex, INFINITE);
    switch (res)
    {
        case WAIT_OBJECT_0:
        {
            break;
        }

        case WAIT_ABANDONED:
        {
            _hMutex = nullptr;
            break;
        }

        default:
        {
            _hMutex = nullptr;
            break;
        }

    }

}


RAII::MutexLock::~MutexLock()
{
    if (_hMutex)
    {
        ReleaseMutex(_hMutex);
    }
}


HANDLE RAII::MutexLock::Get()
{
    return _hMutex;
}