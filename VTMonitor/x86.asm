; base is
; https://github.com/intel/haxm/blob/master/core/vmx_ops.asm
; https://github.com/SinaKarvandi/Hypervisor-From-Scratch/blob/master/Part%206%20-%20Virtualizing%20An%20Already%20Running%20System/MyHypervisorDriver/MyHypervisorDriver/Main.asm

.code _text

VMXSetVMXE PROC
    push    rax
    xor     rax,rax
    mov     rax,cr4
    or      rax,02000h  ; Set the 14th bit
    mov     cr4,rax
    pop     rax
    ret
VMXSetVMXE ENDP

context STRUCT
    _rax dq 0
    _rcx dq 0
    _rdx dq 0
    _rbx dq 0
    _rsp dq 0
    _rbp dq 0
    _rsi dq 0
    _rdi dq 0
    _r8  dq 0
    _r9  dq 0
    _r10 dq 0
    _r11 dq 0
    _r12 dq 0
    _r13 dq 0
    _r14 dq 0
    _r15 dq 0
    _rip dq 0
context ENDS

VMXLaunch PROC
    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; write host rsp
    mov r15, 6C14h
    mov r14, rsp
    sub r14, 8h     ; consider rcx pushed later
    vmwrite r15, r14
    pop r15
    pop r14
    push r14
    push r15

    push rcx ; context
    mov rax, rcx
    mov rcx, (context PTR [rax])._rcx
    mov rdx, (context PTR [rax])._rdx
    mov rbx, (context PTR [rax])._rbx
    mov rbp, (context PTR [rax])._rbp
    mov rsi, (context PTR [rax])._rsi
    mov rdi, (context PTR [rax])._rdi
    mov r8,  (context PTR [rax])._r8
    mov r9,  (context PTR [rax])._r9
    mov r10, (context PTR [rax])._r10
    mov r11, (context PTR [rax])._r11
    mov r12, (context PTR [rax])._r12
    mov r13, (context PTR [rax])._r13
    mov r14, (context PTR [rax])._r14
    mov r15, (context PTR [rax])._r15
    mov rax, (context PTR [rax])._rax
    vmlaunch

    jmp VMXRestoreState
VMXLaunch ENDP

VMXRestoreState PROC
    push rax
    mov rax, [rsp + 8h]
    mov (context PTR [rax])._rcx, rcx
    mov (context PTR [rax])._rdx, rdx
    mov (context PTR [rax])._rbx, rbx
    mov (context PTR [rax])._rbp, rbp
    mov (context PTR [rax])._rsi, rsi
    mov (context PTR [rax])._rdi, rdi
    mov (context PTR [rax])._r8, r8
    mov (context PTR [rax])._r9, r9
    mov (context PTR [rax])._r10, r10
    mov (context PTR [rax])._r11, r11
    mov (context PTR [rax])._r12, r12
    mov (context PTR [rax])._r13, r13
    mov (context PTR [rax])._r14, r14
    mov (context PTR [rax])._r15, r15
    pop rcx
    mov (context PTR [rax])._rax, rcx

    pop r15
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq

    ret
VMXRestoreState ENDP

asm_sli PROC PUBLIC
    STI
    ret
asm_sli ENDP 

asm_cli PROC PUBLIC
    CLI
    ret
asm_cli ENDP 

; get segments
asm_get_CS PROC
    mov     rax, cs
    ret
asm_get_CS ENDP

asm_get_DS PROC
    mov     rax, ds
    ret
asm_get_DS ENDP

asm_get_ES PROC
    mov     rax, es
    ret
asm_get_ES ENDP

asm_get_SS PROC
    mov     rax, ss
    ret
asm_get_SS ENDP

asm_get_FS PROC
    mov     rax, fs
    ret
asm_get_FS ENDP

asm_get_GS PROC
    mov     rax, gs
    ret
asm_get_GS ENDP

asm_get_ldtr PROC
    sldt    rax
    ret
asm_get_ldtr ENDP

asm_get_TR PROC
    str     rax
    ret
asm_get_TR ENDP

asm_get_gdt_base PROC
    LOCAL   gdtr[10]:BYTE
    sgdt    gdtr
    mov     rax, QWORD PTR gdtr[2]
    ret
asm_get_gdt_base ENDP

asm_get_gdt_limit PROC
    LOCAL   gdtr[10]:BYTE
    sgdt    gdtr
    mov     ax, WORD PTR gdtr[0]
    ret
asm_get_gdt_limit ENDP

asm_get_idt_base PROC
    LOCAL   idtr[10]:BYTE
    sidt    idtr
    mov     rax, QWORD PTR idtr[2]
    ret
asm_get_idt_base ENDP

asm_get_idt_limit PROC
    LOCAL   idtr[10]:BYTE
    sidt    idtr
    mov     ax, WORD PTR idtr[0]
    ret
asm_get_idt_limit ENDP

asm_get_dr7 PROC
    mov     rax, dr7
    ret
asm_get_dr7 ENDP

END