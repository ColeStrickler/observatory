#include "helper.h"
#pragma warning(disable: 4996)



std::string DisplayTime(const LARGE_INTEGER& time) 
{
    SYSTEMTIME st;
    FileTimeToSystemTime((FILETIME*)&time, &st);
    char buffer[100];
    sprintf_s(buffer, "%02d:%02d:%02d:%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    std::string ret(buffer);
    return ret;
}

std::string WstringToString(std::wstring wstr)
{
    DWORD len = wcslen(wstr.data()) + 1;
    RAII::NewBuffer strbuffer(len);
    sprintf_s((char*)strbuffer.Get(), len, "%ws", wstr.data());
    std::string ret = std::string((char*)strbuffer.Get());
    return ret;
}

std::string BinaryToString(void* Tgt, DWORD Length)
{
    RAII::NewBuffer buf(Length);
    BYTE* write_ptr = buf.Get();
    BYTE* read_ptr = (BYTE*)Tgt;
    for (DWORD i = 0; i < Length; i++)
    {
        sprintf((char*)write_ptr, "%02X", *read_ptr);

        read_ptr += 1;
        write_ptr += 1;
    }
    std::string ret((char*)buf.Get(), Length);
    return ret;
}