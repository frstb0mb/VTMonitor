#define MSR_IA32_MTRR_CAPABILITIES          0x0FE
#define MSR_IA32_MTRR_PHYSBASE0             0x200
#define MSR_IA32_MTRR_PHYSBASE1             0x202
#define MSR_IA32_MTRR_PHYSBASE2             0x204
#define MSR_IA32_MTRR_PHYSBASE3             0x206
#define MSR_IA32_MTRR_PHYSBASE4             0x208
#define MSR_IA32_MTRR_PHYSBASE5             0x20A
#define MSR_IA32_MTRR_PHYSBASE6             0x20C
#define MSR_IA32_MTRR_PHYSBASE7             0x20E
#define MSR_IA32_MTRR_PHYSBASE8             0x210
#define MSR_IA32_MTRR_PHYSBASE9             0x212
#define MSR_IA32_MTRR_PHYSMASK0             0x201
#define MSR_IA32_MTRR_PHYSMASK1             0x203
#define MSR_IA32_MTRR_PHYSMASK2             0x205
#define MSR_IA32_MTRR_PHYSMASK3             0x207
#define MSR_IA32_MTRR_PHYSMASK4             0x209
#define MSR_IA32_MTRR_PHYSMASK5             0x20B
#define MSR_IA32_MTRR_PHYSMASK6             0x20D
#define MSR_IA32_MTRR_PHYSMASK7             0x20F
#define MSR_IA32_MTRR_PHYSMASK8             0x211
#define MSR_IA32_MTRR_PHYSMASK9             0x213

#define MSR_APIC_BASE                       0x01B
#define MSR_IA32_FEATURE_CONTROL            0x03A

#define MSR_IA32_VMX_BASIC                  0x480
#define MSR_IA32_VMX_PINBASED_CTLS          0x481
#define MSR_IA32_VMX_PROCBASED_CTLS         0x482
#define MSR_IA32_VMX_EXIT_CTLS              0x483
#define MSR_IA32_VMX_ENTRY_CTLS             0x484
#define MSR_IA32_VMX_MISC                   0x485
#define MSR_IA32_VMX_CR0_FIXED0             0x486
#define MSR_IA32_VMX_CR0_FIXED1             0x487
#define MSR_IA32_VMX_CR4_FIXED0             0x488
#define MSR_IA32_VMX_CR4_FIXED1             0x489
#define MSR_IA32_VMX_VMCS_ENUM              0x48A
#define MSR_IA32_VMX_PROCBASED_CTLS2        0x48B
#define MSR_IA32_VMX_EPT_VPID_CAP           0x48C
#define MSR_IA32_VMX_TRUE_PINBASED_CTLS     0x48D
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS    0x48E
#define MSR_IA32_VMX_TRUE_EXIT_CTLS         0x48F
#define MSR_IA32_VMX_TRUE_ENTRY_CTLS        0x490
#define MSR_IA32_VMX_VMFUNC                 0x491

#define MSR_IA32_SYSENTER_CS                0x174
#define MSR_IA32_SYSENTER_ESP               0x175
#define MSR_IA32_SYSENTER_EIP               0x176
#define MSR_IA32_DEBUGCTL                   0x1D9
#define MSR_EFER                            0xC0000080
#define MSR_LSTAR                           0xC0000082


#define MSR_FS_BASE                         0xC0000100
#define MSR_GS_BASE                         0xC0000101
#define MSR_SHADOW_GS_BASE                  0xC0000102

#define MSR_IA32_X2APIC_SIVR                0x80F