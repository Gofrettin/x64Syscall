public x64SyscallCallback
     
.code
     
x64SyscallCallback proc
    nop
    mov r10, rcx
    pop rcx
    pop rax
    nop
    mov QWORD PTR [rsp], rcx
    mov eax, [rsp + 24]
    syscall
    sub rsp, 8
    nop
    jmp QWORD PTR [rsp + 8]
x64SyscallCallback endp
     
end
