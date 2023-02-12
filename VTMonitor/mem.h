#pragma once

#include <ntddk.h>

typedef struct _VirtualMachineState
{
    UINT64 VMXON_REGION;                        // VMXON region
    UINT64 VMCS_REGION;                         // VMCS region
    UINT64 EPTP;                                // Extended-Page-Table Pointer
    UINT64 MSRBitMap;                           // MSRBitMap Virtual Address
    UINT64 MSRBitMapPhysical;                   // MSRBitMap Physical Address
    UINT64 MSREntryLoad;
    UINT64 MSREntryLoadPhysical;
    UINT64 MSRExitLoad;
    UINT64 MSRExitLoadPhysical;
    UINT64 VirtAPIC;
    UINT64 VirtAPICPhysical;
} VirtualMachineState, * PVirtualMachineState;

void ReleaseMemories();
bool AllocateMemories();
PVirtualMachineState GetVMState();