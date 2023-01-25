#include "helper.h"


std::string DisplayTime(const LARGE_INTEGER& time) {
    SYSTEMTIME st;
    FileTimeToSystemTime((FILETIME*)&time, &st);
    char buffer[100];
    sprintf_s(buffer, "%02d:%02d:%02d:%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    std::string ret(buffer);
    return ret;
}