/*
MIT License

Copyright (c) 2020 Sina Karvandi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "ept.h"
#include "msr.h"
#include <intrin.h>
#include "vtm_debug.h"


extern "C" ULONG64 asm_get_rsp(void);


/* Converts Physical Address to Virtual Address */
UINT64 PhysicalAddressToVirtualAddress(UINT64 PhysicalAddress)
{
    PHYSICAL_ADDRESS PhysicalAddr;
    PhysicalAddr.QuadPart = PhysicalAddress;

    return reinterpret_cast<UINT64>(MmGetVirtualForPhysical(PhysicalAddr));
}

/* Converts Virtual Address to Physical Address */
UINT64 VirtualAddressToPhysicalAddress(PVOID VirtualAddress)
{
    return MmGetPhysicalAddress(VirtualAddress).QuadPart;
}

EPT_STATE* EptState = nullptr;

/* Build MTRR Map of current physical addresses */
BOOLEAN EptBuildMtrrMap()
{
    IA32_MTRR_CAPABILITIES_REGISTER MTRRCap;
    IA32_MTRR_PHYSBASE_REGISTER CurrentPhysBase;
    IA32_MTRR_PHYSMASK_REGISTER CurrentPhysMask;
    PMTRR_RANGE_DESCRIPTOR Descriptor;
    ULONG CurrentRegister;
    ULONG NumberOfBitsInMask;


    MTRRCap.Flags = __readmsr(MSR_IA32_MTRR_CAPABILITIES);

    for (CurrentRegister = 0; CurrentRegister < MTRRCap.field.VariableRangeCount; CurrentRegister++)
    {
        // For each dynamic register pair
        CurrentPhysBase.Flags = __readmsr(MSR_IA32_MTRR_PHYSBASE0 + (CurrentRegister * 2));
        CurrentPhysMask.Flags = __readmsr(MSR_IA32_MTRR_PHYSMASK0 + (CurrentRegister * 2));

        // Is the range enabled?
        if (CurrentPhysMask.field.Valid)
        {
            // We only need to read these once because the ISA dictates that MTRRs are to be synchronized between all processors
            // during BIOS initialization.
            Descriptor = &EptState->MemoryRanges[EptState->NumberOfEnabledMemoryRanges++];

            // Calculate the base address in bytes
            Descriptor->PhysicalBaseAddress = CurrentPhysBase.field.PageFrameNumber * PAGE_SIZE;

            // Calculate the total size of the range
            // The lowest bit of the mask that is set to 1 specifies the size of the range
            _BitScanForward64(&NumberOfBitsInMask, CurrentPhysMask.field.PageFrameNumber * PAGE_SIZE);

            // Size of the range in bytes + Base Address
            Descriptor->PhysicalEndAddress = Descriptor->PhysicalBaseAddress + ((1ULL << NumberOfBitsInMask) - 1ULL);

            // Memory Type (cacheability attributes)
            Descriptor->MemoryType = (UCHAR)CurrentPhysBase.field.Type;

            if (Descriptor->MemoryType == MEMORY_TYPE_WRITE_BACK)
            {
                /* This is already our default, so no need to store this range.
                 * Simply 'free' the range we just wrote. */
                EptState->NumberOfEnabledMemoryRanges--;
            }
            //DbgPrint("MTRR Range: Base=0x%llx End=0x%llx Type=0x%x", Descriptor->PhysicalBaseAddress, Descriptor->PhysicalEndAddress, Descriptor->MemoryType);
        }
    }

    //DbgPrint("Total MTRR Ranges Committed: %d", EptState->NumberOfEnabledMemoryRanges);

    return TRUE;
}

/* Get the PML1 entry for this physical address if the page is split. Return NULL if the address is invalid or the page wasn't already split. */
PEPT_PML1_ENTRY EptGetPml1Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
    SIZE_T Directory, DirectoryPointer, PML4Entry;
    PEPT_PML2_ENTRY PML2;
    PEPT_PML1_ENTRY PML1;
    PEPT_PML2_POINTER PML2Pointer;

    Directory = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
    DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
    PML4Entry = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

    // Addresses above 512GB are invalid because it is > physical address bus width 
    if (PML4Entry > 0)
    {
        return NULL;
    }

    PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];

    // Check to ensure the page is split 
    if (PML2->field.LargePage)
    {
        return NULL;
    }

    // Conversion to get the right PageFrameNumber.
    // These pointers occupy the same place in the table and are directly convertable.
    PML2Pointer = (PEPT_PML2_POINTER)PML2;

    // If it is, translate to the PML1 pointer 
    PML1 = (PEPT_PML1_ENTRY)PhysicalAddressToVirtualAddress((UINT64)(PML2Pointer->field.PageFrameNumber * PAGE_SIZE));

    if (!PML1)
    {
        return NULL;
    }

    // Index into PML1 for that address 
    PML1 = &PML1[ADDRMASK_EPT_PML1_INDEX(PhysicalAddress)];

    return PML1;
}


/* Get the PML2 entry for this physical address. */
PEPT_PML2_ENTRY EptGetPml2Entry(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
    SIZE_T Directory, DirectoryPointer, PML4Entry;
    PEPT_PML2_ENTRY PML2;

    Directory = ADDRMASK_EPT_PML2_INDEX(PhysicalAddress);
    DirectoryPointer = ADDRMASK_EPT_PML3_INDEX(PhysicalAddress);
    PML4Entry = ADDRMASK_EPT_PML4_INDEX(PhysicalAddress);

    // Addresses above 512GB are invalid because it is > physical address bus width 
    if (PML4Entry > 0)
    {
        return NULL;
    }

    PML2 = &EptPageTable->PML2[DirectoryPointer][Directory];
    return PML2;
}

/* Set up PML2 Entries */
VOID EptSetupPML2Entry(PEPT_PML2_ENTRY NewEntry, SIZE_T PageFrameNumber)
{
    SIZE_T AddressOfPage;
    SIZE_T CurrentMtrrRange;
    SIZE_T TargetMemoryType;

    /*
      Each of the 512 collections of 512 PML2 entries is setup here.
      This will, in total, identity map every physical address from 0x0 to physical address 0x8000000000 (512GB of memory)

      ((EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex) * 2MB is the actual physical address we're mapping
     */
    NewEntry->field.PageFrameNumber = PageFrameNumber;

    // Size of 2MB page * PageFrameNumber == AddressOfPage (physical memory). 
    AddressOfPage = PageFrameNumber * SIZE_2_MB;

    /* To be safe, we will map the first page as UC as to not bring up any kind of undefined behavior from the
      fixed MTRR section which we are not formally recognizing (typically there is MMIO memory in the first MB).

      I suggest reading up on the fixed MTRR section of the manual to see why the first entry is likely going to need to be UC.
     */
    if (PageFrameNumber == 0)
    {
        NewEntry->field.MemoryType = MEMORY_TYPE_UNCACHEABLE;
        return;
    }

    // Default memory type is always WB for performance. 
    TargetMemoryType = MEMORY_TYPE_WRITE_BACK;

    // For each MTRR range 
    for (CurrentMtrrRange = 0; CurrentMtrrRange < EptState->NumberOfEnabledMemoryRanges; CurrentMtrrRange++)
    {
        // If this page's address is below or equal to the max physical address of the range 
        if (AddressOfPage <= EptState->MemoryRanges[CurrentMtrrRange].PhysicalEndAddress)
        {
            // And this page's last address is above or equal to the base physical address of the range 
            if ((AddressOfPage + SIZE_2_MB - 1) >= EptState->MemoryRanges[CurrentMtrrRange].PhysicalBaseAddress)
            {
                /* If we're here, this page fell within one of the ranges specified by the variable MTRRs
                   Therefore, we must mark this page as the same cache type exposed by the MTRR
                 */
                TargetMemoryType = EptState->MemoryRanges[CurrentMtrrRange].MemoryType;
                // DbgPrint("0x%X> Range=%llX -> %llX | Begin=%llX End=%llX", PageFrameNumber, AddressOfPage, AddressOfPage + SIZE_2_MB - 1, EptState->MemoryRanges[CurrentMtrrRange].PhysicalBaseAddress, EptState->MemoryRanges[CurrentMtrrRange].PhysicalEndAddress);

                // 11.11.4.1 MTRR Precedences 
                if (TargetMemoryType == MEMORY_TYPE_UNCACHEABLE)
                {
                    // If this is going to be marked uncacheable, then we stop the search as UC always takes precedent. 
                    break;
                }
            }
        }
    }

    // Finally, commit the memory type to the entry. 
    NewEntry->field.MemoryType = TargetMemoryType;
}

#ifndef MAXULONG64
#define MAXULONG64 (ULONG64)(-1)
#endif


/* Allocates page maps and create identity page table */
PVMM_EPT_PAGE_TABLE EptAllocateAndCreateIdentityPageTable()
{
    PVMM_EPT_PAGE_TABLE PageTable;
    EPT_PML3_POINTER RWXTemplate;
    EPT_PML2_ENTRY PML2EntryTemplate;
    SIZE_T EntryGroupIndex;
    SIZE_T EntryIndex;

    // Allocate all paging structures as 4KB aligned pages 
    PHYSICAL_ADDRESS MaxSize;

    // Allocate address anywhere in the OS's memory space
    MaxSize.QuadPart = MAXULONG64;

    PageTable = static_cast<PVMM_EPT_PAGE_TABLE>(MmAllocateContiguousMemory((sizeof(VMM_EPT_PAGE_TABLE) / PAGE_SIZE) * PAGE_SIZE, MaxSize));

    if (PageTable == NULL)
    {
        DbgPrint("Failed to allocate memory for PageTable");
        return NULL;
    }

    // Zero out all entries to ensure all unused entries are marked Not Present 
    RtlZeroMemory(PageTable, sizeof(VMM_EPT_PAGE_TABLE));

    // Initialize the dynamic split list which holds all dynamic page splits 
    InitializeListHead(&PageTable->DynamicSplitList);

    // Mark the first 512GB PML4 entry as present, which allows us to manage up to 512GB of discrete paging structures. 
    PageTable->PML4[0].field.PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&PageTable->PML3[0]) / PAGE_SIZE;
    PageTable->PML4[0].field.ReadAccess = 1;
    PageTable->PML4[0].field.WriteAccess = 1;
    PageTable->PML4[0].field.ExecuteAccess = 1;

    /* Now mark each 1GB PML3 entry as RWX and map each to their PML2 entry */

    // Ensure stack memory is cleared
    RWXTemplate.Flags = 0;

    // Set up one 'template' RWX PML3 entry and copy it into each of the 512 PML3 entries 
    // Using the same method as SimpleVisor for copying each entry using intrinsics. 
    RWXTemplate.field.ReadAccess = 1;
    RWXTemplate.field.WriteAccess = 1;
    RWXTemplate.field.ExecuteAccess = 1;

    // Copy the template into each of the 512 PML3 entry slots 
    __stosq((SIZE_T*)&PageTable->PML3[0], RWXTemplate.Flags, VMM_EPT_PML3E_COUNT);

    // For each of the 512 PML3 entries 
    for (EntryIndex = 0; EntryIndex < VMM_EPT_PML3E_COUNT; EntryIndex++)
    {
        // Map the 1GB PML3 entry to 512 PML2 (2MB) entries to describe each large page.
        // NOTE: We do *not* manage any PML1 (4096 byte) entries and do not allocate them.
        PageTable->PML3[EntryIndex].field.PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&PageTable->PML2[EntryIndex][0]) / PAGE_SIZE;
    }

    PML2EntryTemplate.Flags = 0;

    // All PML2 entries will be RWX and 'present' 
    PML2EntryTemplate.field.WriteAccess = 1;
    PML2EntryTemplate.field.ReadAccess = 1;
    PML2EntryTemplate.field.ExecuteAccess = 1;

    // We are using 2MB large pages, so we must mark this 1 here. 
    PML2EntryTemplate.field.LargePage = 1;

    /* For each collection of 512 PML2 entries (512 collections * 512 entries per collection), mark it RWX using the same template above.
       This marks the entries as "Present" regardless of if the actual system has memory at this region or not. We will cause a fault in our
       EPT handler if the guest access a page outside a usable range, despite the EPT frame being present here.
     */
    __stosq((SIZE_T*)&PageTable->PML2[0], PML2EntryTemplate.Flags, VMM_EPT_PML3E_COUNT * VMM_EPT_PML2E_COUNT);

    // For each of the 512 collections of 512 2MB PML2 entries 
    for (EntryGroupIndex = 0; EntryGroupIndex < VMM_EPT_PML3E_COUNT; EntryGroupIndex++)
    {
        // For each 2MB PML2 entry in the collection 
        for (EntryIndex = 0; EntryIndex < VMM_EPT_PML2E_COUNT; EntryIndex++)
        {
            // Setup the memory type and frame number of the PML2 entry. 
            EptSetupPML2Entry(&PageTable->PML2[EntryGroupIndex][EntryIndex], (EntryGroupIndex * VMM_EPT_PML2E_COUNT) + EntryIndex);
        }
    }

    return PageTable;
}


/*
  Initialize EPT for an individual logical processor.
  Creates an identity mapped page table and sets up an EPTP to be applied to the VMCS later.
*/
BOOLEAN EptLogicalProcessorInitialize()
{
    PVMM_EPT_PAGE_TABLE PageTable;
    EPTP EPTP;

    /* Allocate the identity mapped page table*/
    PageTable = EptAllocateAndCreateIdentityPageTable();
    if (!PageTable)
    {
        DbgPrint("Unable to allocate memory for EPT");
        return FALSE;
    }

    // Virtual address to the page table to keep track of it for later freeing 
    EptState->EptPageTable = PageTable;

    EPTP.Flags = 0;

    // For performance, we let the processor know it can cache the EPT.
    EPTP.field.MemoryType = MEMORY_TYPE_WRITE_BACK;

    // We are not utilizing the 'access' and 'dirty' flag features. 
    EPTP.field.EnableAccessAndDirtyFlags = FALSE;

    /*
      Bits 5:3 (1 less than the EPT page-walk length) must be 3, indicating an EPT page-walk length of 4;
      see Section 28.2.2
     */
    EPTP.field.PageWalkLength = 3;

    // The physical page number of the page table we will be using 
    EPTP.field.PageFrameNumber = (SIZE_T)VirtualAddressToPhysicalAddress(&PageTable->PML4) / PAGE_SIZE;

    // We will write the EPTP to the VMCS later 
    EptState->EptPointer = EPTP;

    return TRUE;
}

/* Split 2MB (LargePage) into 4kb pages */
PVMM_EPT_DYNAMIC_SPLIT EptSplitLargePage(PVMM_EPT_PAGE_TABLE EptPageTable, SIZE_T PhysicalAddress)
{
    EPT_PML1_ENTRY EntryTemplate;
    SIZE_T EntryIndex;
    PEPT_PML2_ENTRY TargetEntry;
    EPT_PML2_POINTER NewPointer;

    PVMM_EPT_DYNAMIC_SPLIT NewSplit = nullptr;

    // Find the PML2 entry that's currently used
    TargetEntry = EptGetPml2Entry(EptPageTable, PhysicalAddress);
    if (!TargetEntry)
        return nullptr;

    // If this large page is not marked a large page, that means it's a pointer already.
    // That page is therefore already split.
    if (!TargetEntry->field.LargePage) {
        //Already Splitted
        auto tmp = reinterpret_cast<PEPT_PML2_POINTER>(TargetEntry);
        NewSplit = reinterpret_cast<PVMM_EPT_DYNAMIC_SPLIT>(PhysicalAddressToVirtualAddress(tmp->field.PageFrameNumber * PAGE_SIZE));
        return NewSplit;
    }

    // Allocate the PML1 entries 
    NewSplit = (PVMM_EPT_DYNAMIC_SPLIT)ExAllocatePoolWithTag(NonPagedPool, sizeof(VMM_EPT_DYNAMIC_SPLIT), 'EPT');
    if (!NewSplit) {
        return nullptr;
    }
    RtlZeroMemory(NewSplit, sizeof(VMM_EPT_DYNAMIC_SPLIT));


    // Point back to the entry in the dynamic split for easy reference for which entry that dynamic split is for.
    NewSplit->Entry = TargetEntry;

    // Make a template for RWX 
    EntryTemplate.Flags = 0;
    EntryTemplate.field.ReadAccess = 1;
    EntryTemplate.field.WriteAccess = 1;
    EntryTemplate.field.ExecuteAccess = 1;

    // Copy the template into all the PML1 entries 
    __stosq((SIZE_T*)&NewSplit->PML1[0], EntryTemplate.Flags, VMM_EPT_PML1E_COUNT);


    // Set the page frame numbers for identity mapping.
    for (EntryIndex = 0; EntryIndex < VMM_EPT_PML1E_COUNT; EntryIndex++) {
        // Convert the 2MB page frame number to the 4096 page entry number plus the offset into the frame. 
        NewSplit->PML1[EntryIndex].field.PageFrameNumber = ((TargetEntry->field.PageFrameNumber * SIZE_2_MB) / PAGE_SIZE) + EntryIndex;
    }

    // Allocate a new pointer which will replace the 2MB entry with a pointer to 512 4096 byte entries. 
    NewPointer.Flags = 0;
    NewPointer.field.WriteAccess = 1;
    NewPointer.field.ReadAccess = 1;
    NewPointer.field.ExecuteAccess = 1;
    NewPointer.field.PageFrameNumber = VirtualAddressToPhysicalAddress(&NewSplit->PML1[0]) / PAGE_SIZE;

    // Now, replace the entry in the page table with our new split pointer.
    RtlCopyMemory(TargetEntry, &NewPointer, sizeof(NewPointer));

    return NewSplit;
}

constexpr UINT64 MAX_STACK_PAGE_NUM = 0x10;

bool QueryStackRange(UINT64 &stacktop, UINT64 &pagenum)
{
    // fixme
    // ZwQueryVirtualMemory cannot be used
    pagenum = 4;
    stacktop = asm_get_rsp() & ~(UINT64)(0xFFF);
    stacktop -= PAGE_SIZE * (pagenum - 1);

    return true;
}

// fixme
PVOID mng_for_stack_memory[256] = {};
UINT64 swapped_stack[256] = {};
UINT64 tail = 0;

bool IsSwapped(UINT64 stack)
{
    for (int i = 0; i < 256; i++) {
        if (!swapped_stack[i]) {
            swapped_stack[i] = stack;
            return false;
        }
        if (swapped_stack[i] == stack)
            return true;
    }

    return false;
}

// VMM stack must be protected (stack is shared between VMM and ISR)
bool SwapStack()
{
    PVMM_EPT_PAGE_TABLE EptPageTable = EptState->EptPageTable;
    if (!EptPageTable) {
        return nullptr;
    }

    UINT64 stacktop, pagenum;
    if (!QueryStackRange(stacktop, pagenum)) {
        return nullptr;
    }

    // query swap target
    int swapnum = 0;
    UINT64 swap_stacks[16] = {};
    for (UINT64 i = 0; i < pagenum; i++) {
        UINT64 phyaddr = VirtualAddressToPhysicalAddress(reinterpret_cast<PVOID>(stacktop + 0x1000 * i)) & ~static_cast<UINT64>(0xFFF);
        if (!IsSwapped(phyaddr)) {
            swap_stacks[swapnum] = phyaddr;
            swapnum++;
            DebugVTMON("Replaced: %p\n", reinterpret_cast<PVOID>(stacktop + 0x1000 * i));
        }
    }

    if (swapnum == 0)
        return true;

    PUCHAR guest_rsp = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE * swapnum, 'EPT'));
    if (!guest_rsp) {
        return nullptr;
    }
    RtlSecureZeroMemory(guest_rsp, PAGE_SIZE * swapnum);

    mng_for_stack_memory[tail] = guest_rsp;
    tail++;

    // Replace
    for (int i = 0; i < pagenum; i++) {
        if (!swap_stacks[i])
            continue;

        auto phyaddr = swap_stacks[i];
        PVMM_EPT_DYNAMIC_SPLIT PDE = EptSplitLargePage(EptPageTable, phyaddr);
        if (PDE == nullptr) {
            DbgPrint("cannnot query the pte");
            return false;
        }

        DebugVTMON("NewStack: %p\n", reinterpret_cast<PVOID>(guest_rsp + 0x1000 * i));
        const UINT64 new_pageframe = VirtualAddressToPhysicalAddress(guest_rsp + 0x1000 * i) / PAGE_SIZE;
        PDE->PML1[ADDRMASK_EPT_PML1_INDEX(phyaddr)].field.PageFrameNumber = new_pageframe;

        bool found = false;
        for (int j = 0; j < tail; j++) {
            if (mng_for_stack_memory[j] == PDE) {
                found = true;
                break;
            }
        }
        if (!found) {
            mng_for_stack_memory[tail] = PDE;
            tail++;
        }
    }
    return true;
}

EPT_STATE *GetEPTState()
{
    return EptState;
}


bool EPTInit()
{
    if (EptState) {
        return true;
    }

    EptState = static_cast<EPT_STATE*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(EPT_STATE), 'mem'));
    if (!EptState) {
        return false;
    }
    RtlZeroMemory(EptState, sizeof(EPT_STATE));

    if (!EptBuildMtrrMap()) {
        return false;
    }

    EptLogicalProcessorInitialize();

    return true;
}

void EPTRelease()
{
    for (int i = 0; i < tail; i++) {
        if (mng_for_stack_memory[i]) {
            ExFreePool(mng_for_stack_memory[i]);
            mng_for_stack_memory[i] = nullptr;
        }
    }
    tail = 0;
    MmFreeContiguousMemory(EptState->EptPageTable);
    EptState->EptPageTable = nullptr;
    ExFreePool(EptState);
    EptState = nullptr;
}