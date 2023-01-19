#pragma once
#ifdef _CONSOLE
#include <winnt.h>
#else
#include <ntddk.h>
#endif

#define VTMONITOR_DEVICETYPE 0x8001
#define IOCTL_VTMONITOR_START   CTL_CODE(VTMONITOR_DEVICETYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VTMONITOR_END     CTL_CODE(VTMONITOR_DEVICETYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _vtmif {
    ULONG exitcode;

    // For exception
    UINT64 error;       // Exception error code
    UINT64 vec;         // Exception vector
    UINT64 except_addr; // For #PF

    CONTEXT context;
} vtmif;

#define EXCEPTION_DE    0
#define EXCEPTION_DB    1
#define EXCEPTION_NMI   2
#define EXCEPTION_BP    3
#define EXCEPTION_OF    4
#define EXCEPTION_BR    5
#define EXCEPTION_UD    6
#define EXCEPTION_NM    7
#define EXCEPTION_DF    8
#define EXCEPTION_TS    10
#define EXCEPTION_NP    11
#define EXCEPTION_SS    12
#define EXCEPTION_GP    13
#define EXCEPTION_PF    14
#define EXCEPTION_MF    16
#define EXCEPTION_AC    17
#define EXCEPTION_MC    18
#define EXCEPTION_XM    19
#define EXCEPTION_VE    20
#define EXCEPTION_CP    21
#define EXCEPTION_HV    28
#define EXCEPTION_VC    29
#define EXCEPTION_SX    30
