.code

syscall_stub PROC
push rbp
mov rbp, rsp

mov rax, [rsp+30h] ; syscall num
mov rsp, [rsp+38h] ; guest stack
mov r10, rcx
syscall

mov rsp, rbp
pop rbp

ret
syscall_stub ENDP

END