

.CODE

NtAllocateVirtualMemory PROC
  mov         r10,rcx
  mov         eax,18h
  syscall
  ret
NtAllocateVirtualMemory ENDP                        


NtWriteVirtualMemory PROC
    mov         r10,rcx
    mov         eax,3Ah
    syscall
    ret
NtWriteVirtualMemory ENDP


NtCreateThreadEx PROC
    mov         r10,rcx
    mov         eax,0C7h
    syscall
    ret
NtCreateThreadEx ENDP


NtWaitForSingleObject PROC
    mov         r10,rcx
    mov         eax,4
    syscall
    ret
NtWaitForSingleObject ENDP


END