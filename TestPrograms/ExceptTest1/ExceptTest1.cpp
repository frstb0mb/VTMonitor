#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>

int main()
{
    int y = 0;
    __try {
        auto x = 1 / y;
        printf("%d\n", x);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("Zero Divided\n");
    }
}