#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>

LONG WINAPI Handler(struct _EXCEPTION_POINTERS* ExceptionInfo) {
    printf("[EXCEPTIONHANDLER] VEH\n");
    return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
    AddVectoredExceptionHandler(1, Handler);
    auto mem = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT, PAGE_READONLY);
    if (!mem) {
        printf("Failed\n");
        return 0;
    }

    __try {
        *(PBYTE)mem = 1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[EXCEPTIONHANDLER] SEH\n");
    }
}
