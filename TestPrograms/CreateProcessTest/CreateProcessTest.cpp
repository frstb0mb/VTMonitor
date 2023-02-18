#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int main()
{
    wchar_t cmd[] = L"notepad";
    STARTUPINFOW si = {};
    PROCESS_INFORMATION pi = {};
    CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
    WaitForSingleObject(pi.hProcess, 1000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
