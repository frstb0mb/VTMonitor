#include "mem.h"
#include <ntddk.h>
#include <intrin.h>
#include "vtm_debug.h"
#include "vmx.h"
#include "msr.h"

#define POOLTAG 'VTMN'
#define ALIGNMENT_PAGE_SIZE 4096
#define VMCS_SIZE           4096
#define VMXON_SIZE          4096

typedef union _IA32_VMX_BASIC_MSR
{
    ULONG64 All;
    struct
    {
        ULONG32 RevisionIdentifier : 31;   // [0-30]
        ULONG32 Reserved1 : 1;             // [31]
        ULONG32 RegionSize : 12;           // [32-43]
        ULONG32 RegionClear : 1;           // [44]
        ULONG32 Reserved2 : 3;             // [45-47]
        ULONG32 SupportedIA64 : 1;         // [48]
        ULONG32 SupportedDualMoniter : 1;  // [49]
        ULONG32 MemoryType : 4;            // [50-53]
        ULONG32 VmExitReport : 1;          // [54]
        ULONG32 VmxCapabilityHint : 1;     // [55]
        ULONG32 Reserved3 : 8;             // [56-63]
    } Fields;
} IA32_VMX_BASIC_MSR, *PIA32_VMX_BASIC_MSR;


BOOLEAN AllocateMSRBitmap(PVirtualMachineState vmState)
{
    PVOID MSRBitMap = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
    if (MSRBitMap == NULL) {
        DebugVTMON("%s Failed Memory Allocation", __FUNCTION__);
        return FALSE;
    }

    RtlZeroMemory(MSRBitMap, PAGE_SIZE);
    vmState->MSRBitMap = reinterpret_cast<UINT64>(MSRBitMap);
    vmState->MSRBitMapPhysical = MmGetPhysicalAddress(MSRBitMap).QuadPart;

    return TRUE;
}

BOOLEAN AllocateMSRControlInfo(PVirtualMachineState vmState)
{
    PVOID MSREntryLoad = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
    if (MSREntryLoad == NULL) {
        DebugVTMON("%s Failed Memory Allocation", __FUNCTION__);
        return FALSE;
    }
    PVOID MSRExitLoad = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
    if (MSRExitLoad == NULL) {
        DebugVTMON("%s Failed Memory Allocation", __FUNCTION__);
        return FALSE;
    }

    RtlZeroMemory(MSREntryLoad, PAGE_SIZE);
    RtlZeroMemory(MSRExitLoad, PAGE_SIZE);
    vmState->MSREntryLoad = reinterpret_cast<UINT64>(MSREntryLoad);
    vmState->MSRExitLoad = reinterpret_cast<UINT64>(MSRExitLoad);
    vmState->MSREntryLoadPhysical = MmGetPhysicalAddress(MSREntryLoad).QuadPart;
    vmState->MSRExitLoadPhysical = MmGetPhysicalAddress(MSRExitLoad).QuadPart;

    return TRUE;
}

BOOLEAN AllocateVirtAPIC(PVirtualMachineState vmState)
{
    PVOID mem = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, POOLTAG);
    if (mem == NULL) {
        DebugVTMON("%s Failed Memory Allocation", __FUNCTION__);
        return FALSE;
    }

    RtlZeroMemory(mem, PAGE_SIZE);
    vmState->VirtAPIC = reinterpret_cast<UINT64>(mem);
    vmState->VirtAPICPhysical = MmGetPhysicalAddress(mem).QuadPart;

    return TRUE;
}

#ifndef MAXULONG64
#define MAXULONG64 (ULONG64)(-1)
#endif

// allocate memory for VMXON or VMCS region
// return allocated Physical Buffer
UINT64 InitVTXRegion(size_t allocsize, size_t alignsize)
{
    allocsize *= 2; // for alignsize
    
    PHYSICAL_ADDRESS PhysicalMax = { };
    PhysicalMax.QuadPart = MAXULONG64;
    auto buffer = static_cast<char*>(MmAllocateContiguousMemory(allocsize + alignsize, PhysicalMax));
    if (!buffer) {
        DebugVTMON("[%s] Failed MmAllocateContiguousMemory", __FUNCTION__);
        return 0;
    }

    RtlSecureZeroMemory(buffer, allocsize + alignsize);

    UINT64 phybuf =  MmGetPhysicalAddress(buffer).QuadPart;
    UINT64 aligned_physical_buffer  =    static_cast<UINT64>((phybuf + alignsize - 1)) & ~(alignsize - 1);
    UINT64 aligned_virtual_buffer   =    reinterpret_cast<UINT64>((buffer + alignsize - 1)) & ~(alignsize - 1);

    IA32_VMX_BASIC_MSR basic = {};
    basic.All = __readmsr(MSR_IA32_VMX_BASIC);

    *reinterpret_cast<UINT64 *>(aligned_virtual_buffer) = basic.Fields.RevisionIdentifier;

    return aligned_physical_buffer;
}

BOOLEAN AllocateVMXMem(IN PVirtualMachineState vmState)
{
    auto vmxon_region = InitVTXRegion(VMXON_SIZE, ALIGNMENT_PAGE_SIZE);
    if (!vmxon_region) {
        DebugVTMON("[%s] Failed InitVTXRegion", __FUNCTION__);
        return FALSE;
    }

    auto vmcs_region = InitVTXRegion(VMCS_SIZE, ALIGNMENT_PAGE_SIZE);
    if (!vmcs_region) {
        DebugVTMON("[%s] Failed InitVTXRegion", __FUNCTION__);
        ExFreePool(reinterpret_cast<PVOID>(vmxon_region));
        return FALSE;
    }

    vmState->VMXON_REGION = vmxon_region;
    vmState->VMCS_REGION = vmcs_region;

    return TRUE;
}

PVirtualMachineState vtx_mem = nullptr;


void ReleaseMemories()
{
    if (!vtx_mem)
        return;

    if (vtx_mem->MSRBitMap)
        ExFreePool(reinterpret_cast<PVOID>(vtx_mem->MSRBitMap));
    if (vtx_mem->MSREntryLoad)
        ExFreePool(reinterpret_cast<PVOID>(vtx_mem->MSREntryLoad));
    if (vtx_mem->MSRExitLoad)
        ExFreePool(reinterpret_cast<PVOID>(vtx_mem->MSRExitLoad));
    if (vtx_mem->VirtAPIC)
        ExFreePool(reinterpret_cast<PVOID>(vtx_mem->VirtAPIC));

    PHYSICAL_ADDRESS PhysicalAddr;
    PhysicalAddr.QuadPart = vtx_mem->VMCS_REGION;
    if (PhysicalAddr.QuadPart)
        MmFreeContiguousMemory(MmGetVirtualForPhysical(PhysicalAddr));
    PhysicalAddr.QuadPart = vtx_mem->VMXON_REGION;
    if (PhysicalAddr.QuadPart)
        MmFreeContiguousMemory(MmGetVirtualForPhysical(PhysicalAddr));

    ExFreePool(vtx_mem);
    vtx_mem = nullptr;
}

bool AllocateMemories()
{
    if (vtx_mem)
        return true;

    vtx_mem = (PVirtualMachineState)ExAllocatePoolWithTag(NonPagedPool, sizeof(VirtualMachineState), POOLTAG);
    if (!vtx_mem)
        return false;

    RtlZeroMemory(vtx_mem, sizeof(vtx_mem));

    if (!AllocateVMXMem(vtx_mem)      ||
        !AllocateMSRBitmap(vtx_mem) ||
        !AllocateMSRControlInfo(vtx_mem) ||
        !AllocateVirtAPIC(vtx_mem)) {
            ReleaseMemories();
            vtx_mem = nullptr;
            return false;
    }

    return true;
}

PVirtualMachineState GetVMState()
{
    return vtx_mem;
}