// base is
// https://github.com/SinaKarvandi/Hypervisor-From-Scratch/tree/master/Part%206%20-%20Virtualizing%20An%20Already%20Running%20System/MyHypervisorDriver

#include "common.h"
#include <ntddk.h>
#include <intrin.h>
#include "vmx.h"
#include "msr.h"
#include "mem.h"
#include "vtm_debug.h"
#include "ept.h"

extern "C" void VMXSetVMXE(void);
extern "C" VOID VMXRestoreState();
extern "C" void asm_sli();
extern "C" void asm_cli();
extern "C" void VMXLaunch(PVOID, bool);
extern "C" USHORT asm_get_CS(VOID);
extern "C" USHORT asm_get_DS(VOID);
extern "C" USHORT asm_get_ES(VOID);
extern "C" USHORT asm_get_SS(VOID);
extern "C" USHORT asm_get_FS(VOID);
extern "C" USHORT asm_get_GS(VOID);
extern "C" USHORT asm_get_ldtr(VOID);
extern "C" USHORT asm_get_TR(VOID);
extern "C" USHORT asm_get_idt_limit(VOID);
extern "C" USHORT asm_get_gdt_limit(VOID);
extern "C" ULONG64 asm_get_gdt_base(void);
extern "C" ULONG64 asm_get_idt_base(void);
extern "C" ULONG64 asm_get_dr7(void);
extern "C" void asm_set_cr2(UINT64);


BOOLEAN ExecVMXON(IN PVirtualMachineState vmState)
{
    if (!vmState || !vmState->VMXON_REGION)
        return false;

    int status = __vmx_on(&vmState->VMXON_REGION);
    if (status) {
        DebugVTMON("[%s] Failed __vmx_on Status:%x", __FUNCTION__, status);
        return FALSE;
    }

    return TRUE;
}

BOOLEAN ClearVMCS(IN PVirtualMachineState vmState)
{

    // Clear the state of the VMCS to inactive
    int status = __vmx_vmclear(&vmState->VMCS_REGION);
    if (status) {
        DebugVTMON("[%s] Failed __vmx_vmclear Status:%x", __FUNCTION__, status);
        __vmx_off();
        return FALSE;
    }
    return TRUE;
}

BOOLEAN LoadVMCS(IN PVirtualMachineState vmState)
{
    int status = __vmx_vmptrld(&vmState->VMCS_REGION);
    if (status) {
        DebugVTMON("[%s] Failed vmptrld", __FUNCTION__);
        return FALSE;
    }
    return TRUE;
}

typedef union SEGMENT_ATTRIBUTES
{
    USHORT UCHARs;
    struct
    {
        USHORT TYPE : 4;              /* 0;  Bit 40-43 */
        USHORT S : 1;                 /* 4;  Bit 44 */
        USHORT DPL : 2;               /* 5;  Bit 45-46 */
        USHORT P : 1;                 /* 7;  Bit 47 */

        USHORT AVL : 1;               /* 8;  Bit 52 */
        USHORT L : 1;                 /* 9;  Bit 53 */
        USHORT DB : 1;                /* 10; Bit 54 */
        USHORT G : 1;                 /* 11; Bit 55 */
        USHORT GAP : 4;

    } Fields;
} SEGMENT_ATTRIBUTES;

typedef struct SEGMENT_SELECTOR
{
    USHORT SEL;
    SEGMENT_ATTRIBUTES ATTRIBUTES;
    ULONG32 LIMIT;
    ULONG64 BASE;
} SEGMENT_SELECTOR, *PSEGMENT_SELECTOR;

typedef struct _SEGMENT_DESCRIPTOR
{
    USHORT LIMIT0;
    USHORT BASE0;
    UCHAR  BASE1;
    UCHAR  ATTR0;
    UCHAR  LIMIT1ATTR1;
    UCHAR  BASE2;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

BOOLEAN GetSegmentDescriptor(IN PSEGMENT_SELECTOR segment_selector, IN USHORT selector, IN PUCHAR gdt_base)
{
    PSEGMENT_DESCRIPTOR SegDesc;

    if (!segment_selector)
        return FALSE;

    if (selector & 0x4)
        return FALSE;

    SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)gdt_base + (selector & ~0x7));

    segment_selector->SEL = selector;
    segment_selector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
    segment_selector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
    segment_selector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

    if (!(SegDesc->ATTR0 & 0x10)) { // LA_ACCESSED
        ULONG64 tmp;
        // this is a TSS or callgate etc, save the base high part
        tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
        segment_selector->BASE = (segment_selector->BASE & 0xffffffff) | (tmp << 32);
    }

    if (segment_selector->ATTRIBUTES.Fields.G) {
        // 4096-bit granularity is enabled for this segment, scale the limit
        segment_selector->LIMIT = (segment_selector->LIMIT << 12) + 0xfff;
    }

    return TRUE;
}

enum class SEGREGS
{
    ES = 0,
    CS,
    SS,
    DS,
    FS,
    GS,
    LDTR,
    TR
};

void FillGuestSelectorData(PVOID gdt_base, SEGREGS segment, USHORT selector)
{
    SEGMENT_SELECTOR segment_selector = {};
    ULONG            uAccessRights;

    GetSegmentDescriptor(&segment_selector, selector, (PUCHAR)gdt_base);
    uAccessRights = ((PUCHAR)& segment_selector.ATTRIBUTES)[0] + (((PUCHAR)& segment_selector.ATTRIBUTES)[1] << 12);

    if (!selector)
        uAccessRights |= 0x10000;

    __vmx_vmwrite(GUEST_ES_SELECTOR + static_cast<size_t>(segment) * 2, selector);
    __vmx_vmwrite(GUEST_ES_LIMIT + static_cast<size_t>(segment) * 2, segment_selector.LIMIT);
    __vmx_vmwrite(GUEST_ES_AR_BYTES + static_cast<size_t>(segment) * 2, uAccessRights);
    __vmx_vmwrite(GUEST_ES_BASE + static_cast<size_t>(segment) * 2, segment_selector.BASE);
}

ULONG AdjustControls(IN ULONG ctl, IN ULONG msr)
{
    ULARGE_INTEGER MsrValue = {};

    MsrValue.QuadPart = __readmsr(msr);
    ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
    ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
    return ctl;
}

BOOLEAN InitVMCS(PVirtualMachineState vtx_mem)
{
    asm_cli();
    if (!ClearVMCS(vtx_mem))
        return FALSE;
    
    if (!LoadVMCS(vtx_mem))
        return FALSE;

    return TRUE;
}


union INTERRUPT_INFO {
    struct {
        UINT32 Vector : 8;
        /* 0=Ext Int, 1=Rsvd, 2=NMI, 3=Exception, 4=Soft INT,
        * 5=Priv Soft Trap, 6=Unpriv Soft Trap, 7=Other */
        UINT32 InterruptType : 3;
        UINT32 DeliverCode : 1;  /* 0=Do not deliver, 1=Deliver */
        UINT32 Reserved : 19;
        UINT32 Valid : 1;         /* 0=Not valid, 1=Valid. Must be checked first */
    } field;
    UINT32 Flags;
};
INTERRUPT_INFO Inject = {};
UINT64 exit_len = 0;
UINT64 last_gs = 0;

BOOLEAN WriteVMCSFields(IN PVirtualMachineState vmState, vtmif *vmdata, bool resume)
{
    // setting host segments
#define VMWRITE_HOSTSEGMENTSELECTOR(segment) __vmx_vmwrite(HOST_## segment ## _SELECTOR, asm_get_ ## segment() & 0xF8)

    VMWRITE_HOSTSEGMENTSELECTOR(ES);
    VMWRITE_HOSTSEGMENTSELECTOR(CS);
    VMWRITE_HOSTSEGMENTSELECTOR(SS);
    VMWRITE_HOSTSEGMENTSELECTOR(DS);
    VMWRITE_HOSTSEGMENTSELECTOR(FS);
    VMWRITE_HOSTSEGMENTSELECTOR(GS);
    VMWRITE_HOSTSEGMENTSELECTOR(TR);

    __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
    __vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);

    auto gdt_base = asm_get_gdt_base();
    // setting guest segments
    FillGuestSelectorData((PVOID)gdt_base, SEGREGS::ES, vmdata->context.SegEs);
    FillGuestSelectorData((PVOID)gdt_base, SEGREGS::CS, vmdata->context.SegCs);
    FillGuestSelectorData((PVOID)gdt_base, SEGREGS::SS, vmdata->context.SegSs);
    FillGuestSelectorData((PVOID)gdt_base, SEGREGS::DS, vmdata->context.SegDs);
    FillGuestSelectorData((PVOID)gdt_base, SEGREGS::FS, vmdata->context.SegFs);
    FillGuestSelectorData((PVOID)gdt_base, SEGREGS::GS, vmdata->context.SegGs);
    FillGuestSelectorData((PVOID)gdt_base, SEGREGS::LDTR, asm_get_ldtr());
    FillGuestSelectorData((PVOID)gdt_base, SEGREGS::TR, asm_get_TR());

   __vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));

    UINT64 msr_control_count = 0;
    if ((last_gs>>63) != 1 || (vmdata->context.SegCs & 0x1)) {
        // guest is in usermode
        auto usergs = __readmsr(MSR_SHADOW_GS_BASE);
        auto kernelgs = __readmsr(MSR_GS_BASE);
        __vmx_vmwrite(GUEST_GS_BASE, usergs);
        msr_control_count = 1;
        auto msr_entry_control = reinterpret_cast<msr_control_entry*>(vmState->MSREntryLoad);
        msr_entry_control[0].index = MSR_SHADOW_GS_BASE;
        msr_entry_control[0].data = kernelgs;
        auto msr_exit_control = reinterpret_cast<msr_control_entry*>(vmState->MSRExitLoad);
        msr_exit_control[0].index = MSR_SHADOW_GS_BASE;
        msr_exit_control[0].data = usergs;

        __vmx_vmwrite(VM_ENTRY_MSR_LOAD_ADDR, vmState->MSREntryLoadPhysical);
        __vmx_vmwrite(VM_EXIT_MSR_LOAD_ADDR, vmState->MSRExitLoadPhysical);
    }
    else {
        __vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
    }

    __vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, msr_control_count);
    __vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, msr_control_count);

    __vmx_vmwrite(GUEST_CR0, __readcr0());
    __vmx_vmwrite(GUEST_CR3, __readcr3());
    __vmx_vmwrite(GUEST_CR4, __readcr4());

    // For debugging
    // default is 0x400
    __vmx_vmwrite(GUEST_DR7, asm_get_dr7());

    __vmx_vmwrite(HOST_CR0, __readcr0());
    __vmx_vmwrite(HOST_CR3, __readcr3());
    __vmx_vmwrite(HOST_CR4, __readcr4());

    __vmx_vmwrite(GUEST_GDTR_BASE, asm_get_gdt_base());
    __vmx_vmwrite(GUEST_IDTR_BASE, asm_get_idt_base());
    __vmx_vmwrite(GUEST_GDTR_LIMIT, asm_get_gdt_limit());
    __vmx_vmwrite(GUEST_IDTR_LIMIT, asm_get_idt_limit());

    __vmx_vmwrite(GUEST_RFLAGS, static_cast<ULONG64>(vmdata->context.EFlags));

    __vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

    SEGMENT_SELECTOR segment_selector = {};
    GetSegmentDescriptor(&segment_selector, asm_get_TR(), (PUCHAR)asm_get_gdt_base());
    __vmx_vmwrite(HOST_TR_BASE, segment_selector.BASE);

    __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

    __vmx_vmwrite(HOST_GDTR_BASE, asm_get_gdt_base());
    __vmx_vmwrite(HOST_IDTR_BASE, asm_get_idt_base());

    __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));

    __vmx_vmwrite(MSR_BITMAP, vmState->MSRBitMapPhysical);

    __vmx_vmwrite(GUEST_IA32_EFER, (__readmsr(MSR_EFER) & ~1)); // clear SCE
    __vmx_vmwrite(HOST_IA32_EFER, __readmsr(MSR_EFER));

    __vmx_vmwrite(GUEST_RSP, vmdata->context.Rsp);
    __vmx_vmwrite(GUEST_RIP, vmdata->context.Rip);

    __vmx_vmwrite(HOST_RIP, (ULONG64)VMXRestoreState);

    // host stack is written when vmlaunch is executed

    if (!resume) {
        __vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL); // unused
        __vmx_vmwrite(TSC_OFFSET, 0);
        __vmx_vmwrite(TSC_OFFSET_HIGH, 0);

        __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
        __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

        __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

        __vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);

        __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_TPR_SHADOW | CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
        __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP | CPU_BASED_CTL2_ENABLE_EPT | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS, MSR_IA32_VMX_PROCBASED_CTLS2));

        __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT | PIN_BASED_VM_EXECUTION_CONTROLS_NMI_EXITING, MSR_IA32_VMX_PINBASED_CTLS));
        __vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_LOAD_HOST_EFER, MSR_IA32_VMX_EXIT_CTLS));
        __vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE | VM_ENTRY_LOAD_GUEST_EFER, MSR_IA32_VMX_ENTRY_CTLS));

        __vmx_vmwrite(CR3_TARGET_COUNT, 0);
        __vmx_vmwrite(CR3_TARGET_VALUE0, 0);
        __vmx_vmwrite(CR3_TARGET_VALUE1, 0);
        __vmx_vmwrite(CR3_TARGET_VALUE2, 0);
        __vmx_vmwrite(CR3_TARGET_VALUE3, 0);

        __vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
        __vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);
        __vmx_vmwrite(CR0_READ_SHADOW, 0);
        __vmx_vmwrite(CR4_READ_SHADOW, 0);

        __vmx_vmwrite(EPT_POINTER, GetEPTState()->EptPointer.Flags);
    }

    if (vmdata->valid_inject || !(vmdata->context.SegCs & 0x1)) {
        // disable APIC in guest kernel(x2APIC is assumed)
        // Using CLI may cause BSOD(At least, IF is checked by PF-handler)
        // MSR bitmap cannnot be used
        UINT64 sivr = __readmsr(MSR_IA32_X2APIC_SIVR);
        __writemsr(MSR_IA32_X2APIC_SIVR, sivr & ~static_cast<UINT64>(1<<8));

        __vmx_vmwrite(EXCEPTION_BITMAP, 1 << EXCEPTION_BP);
    }
    else {
        // Host application handles all exceptions.(this is simple way)
        __vmx_vmwrite(EXCEPTION_BITMAP, ~static_cast<UINT64>(0));
    }

    if (vmdata->valid_inject) {
        Inject.field.Valid = TRUE;
        __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, Inject.Flags);
        if (Inject.field.DeliverCode)
            __vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, vmdata->error);
        if (exit_len)
            __vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, exit_len);
        if (vmdata->vec == EXCEPTION_PF)
            asm_set_cr2(vmdata->except_addr);

        vmdata->valid_inject = FALSE;
    }

    return TRUE;
}

VOID QuerExceptionInfo(UINT64 inttype)
{
    Inject.field.Valid = TRUE;
    Inject.field.InterruptType = 3;
    Inject.field.Vector = static_cast<UINT32>(inttype);
    Inject.field.DeliverCode = FALSE;

    exit_len = 0;

    switch (inttype) {
        case EXCEPTION_DB :
            Inject.field.InterruptType = 5;
            __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &exit_len);
            break;
        case EXCEPTION_BP :
        case EXCEPTION_OF :
            Inject.field.InterruptType = 6;
            __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &exit_len);
            break;
        case EXCEPTION_DF :
        case EXCEPTION_TS :
        case EXCEPTION_NP :
        case EXCEPTION_SS :
        case EXCEPTION_GP :
        case EXCEPTION_PF :
        case EXCEPTION_AC :
        case EXCEPTION_SX :
            Inject.field.DeliverCode = TRUE;
            break;
        default :
            break;
    }
}

bool Handler(vtmif *vmdata)
{
    UINT64 exit_reason = 0;
    UINT64 guest_rip = 0, guest_rsp = 0;
    __vmx_vmread(VM_EXIT_REASON, &exit_reason);
    __vmx_vmread(GUEST_RIP, &guest_rip);
    __vmx_vmread(GUEST_RSP, &guest_rsp);
    DebugVTMON("ExitReason: %llx %llx %llx\n", exit_reason, guest_rip, guest_rsp);

    bool is_continue = false;
    UINT64 inst_len = 0;
    switch (exit_reason) {
        case 0:
        {
            UINT64 intr_info = 0;
            vmx_exit_intr_info info = {};
            __vmx_vmread(VM_EXIT_INTR_INFO, &intr_info);
            info.raw = static_cast<UINT32>(intr_info);
            vmdata->vec = info.field.vec;

            switch(vmdata->vec) {
                case EXCEPTION_UD:
                    __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);
                    break;

                case EXCEPTION_PF:
                    UINT64 except_addr;
                    __vmx_vmread(EXIT_QUALIFICATION, &except_addr);
                    vmdata->except_addr = except_addr;

                default:
                    vmdata->valid_inject = TRUE;
                    QuerExceptionInfo(vmdata->vec);
                    break;
            }
            UINT64 intr_err = 0;
            __vmx_vmread(VM_EXIT_INTR_ERROR_CODE, &intr_err);
            vmdata->error = intr_err;
            break;
        }
        case 1:
        {
            if (!(vmdata->context.SegCs & 0x1)) {
                asm_sli();
                //__halt();
                asm_cli();
                is_continue = true;
            }
            break;
        }
        case 0xa:
        {
            INT32 cpu_info[4] = {};
            __cpuidex(cpu_info, static_cast<int>(vmdata->context.Rax), static_cast<int>(vmdata->context.Rcx));
            vmdata->context.Rax = cpu_info[0];
            vmdata->context.Rbx = cpu_info[1];
            vmdata->context.Rcx = cpu_info[2];
            vmdata->context.Rdx = cpu_info[3];
            __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);
            is_continue = true;
            break;
        }
        case 0x1c:
        {
            UINT64 info = 0;
            vmx_exit_qualification_ctr detail;
            __vmx_vmread(EXIT_QUALIFICATION, &info);
            detail.raw = info;
            if (detail.field.creg == 3) {
                UINT64 *regs = &(vmdata->context.Rax);
                if (detail.field.type == 0)
                {
                    // collapse!
                }
                else if (detail.field.type == 1)
                {
                    regs[detail.field.gpr] = __readcr3();
                }
                __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &inst_len);
            }
            is_continue = true;
            break;
        }

        // currently other exception handling is not supported :<
        default:
            break;
    }

    vmdata->exitcode = static_cast<ULONG>(exit_reason);
    vmdata->context.Rip = guest_rip + inst_len;
    vmdata->context.Rsp = guest_rsp;

    return is_continue;
}

void StartVirtualization(vtmif *vmdata)
{
    auto vtx_mem = GetVMState();
    if (!vtx_mem)
        return;

    KIRQL cur_irql = KeGetCurrentIrql();
    if (cur_irql < DISPATCH_LEVEL)
        KeRaiseIrql(DISPATCH_LEVEL, &cur_irql);

    KeMemoryBarrier();

    VMXSetVMXE();

    if (ExecVMXON(vtx_mem) && SwapStack()) {
        if (InitVMCS(vtx_mem)) {
            bool resume = false;
            do {
                WriteVMCSFields(vtx_mem, vmdata, resume);
                VMXLaunch(&(vmdata->context.Rax), resume);
                resume = true;
                // store guest state
                UINT64 guest_rflags = 0;
                __vmx_vmread(GUEST_RFLAGS, &guest_rflags);
                vmdata->context.EFlags = static_cast<ULONG>(guest_rflags);

                UINT64 guest_selector = 0;
                __vmx_vmread(GUEST_ES_SELECTOR, &guest_selector);
                vmdata->context.SegEs = static_cast<USHORT>(guest_selector);
                __vmx_vmread(GUEST_CS_SELECTOR, &guest_selector);
                vmdata->context.SegCs = static_cast<USHORT>(guest_selector);
                __vmx_vmread(GUEST_SS_SELECTOR, &guest_selector);
                vmdata->context.SegSs = static_cast<USHORT>(guest_selector);
                __vmx_vmread(GUEST_DS_SELECTOR, &guest_selector);
                vmdata->context.SegDs = static_cast<USHORT>(guest_selector);
                __vmx_vmread(GUEST_FS_SELECTOR, &guest_selector);
                vmdata->context.SegFs = static_cast<USHORT>(guest_selector);
                __vmx_vmread(GUEST_GS_SELECTOR, &guest_selector);
                vmdata->context.SegGs = static_cast<USHORT>(guest_selector);

                __vmx_vmread(GUEST_GS_BASE, &last_gs);

                // Enable APIC
                if (vmdata->context.SegCs & 0x1) {
                    UINT64 sivr = __readmsr(MSR_IA32_X2APIC_SIVR);
                    __writemsr(MSR_IA32_X2APIC_SIVR, sivr | static_cast<UINT64>(1<<8));
                }
            } while(Handler(vmdata));

            __vmx_vmclear(&vtx_mem->VMCS_REGION);
        }

        __vmx_off();
        asm_sli();
    }

    if (cur_irql < DISPATCH_LEVEL)
        KeLowerIrql(cur_irql);

    return;
}