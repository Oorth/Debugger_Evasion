;ml64 /c /Fl debug_check.asm

; Check if debugger is present by reading the PEB flag directly
; Compatible with x64 architecture

.code

IsDebuggerPresentASM PROC
    xor rax, rax                  ; Clear RAX to ensure higher bits are zero
    mov rcx, gs:[60h]             ; Get PEB base address from GS:[0x60]
    mov al, byte ptr [rcx+2]      ; Read BeingDebugged flag (offset 0x2)
    ret
IsDebuggerPresentASM ENDP


DetectHardwareBreakpointsASM PROC
    push rbx                        ; Save registers to avoid corrupting them

    mov rax, dr0
    mov rbx, dr1
    mov rcx, dr2
    mov rdx, dr3

    or rax, rbx                     
    or rax, rcx                     
    or rax, rdx

    setnz al                        ; If reg set, AL = 1, else AL = 0
    movzx rax, al                   ; Zero-extend AL to RAX

    pop rbx                         
DetectHardwareBreakpointsASM ENDP

OverwriteDebugPort PROC
    mov     rax, gs:[60h]               ; Get PEB base address
    mov     rcx, 0                      ; Move 0 into RCX (temporary register)
    mov     [rax + 20h], rcx            ; Clear DebugPort by writing 0
    ret                                 ; Return from procedure
OverwriteDebugPort ENDP

CrashOnDebuggerAttach PROC
    mov rax, gs:[60h]          ; Get PEB base address
    mov rcx, 0FFFFFFFFFFFFFFFFh ; Load -1 into RCX
    mov [rax + 18h], rcx       ; Move RCX (-1) into DebugObjectHandle
    ret
CrashOnDebuggerAttach ENDP

END

; Just storing some code which acts like garbage
GarbageCodeLabel:
    db  0xCC, 0x90, 0x90, 0xCC          ; INT 3, NOP, NOP, INT 3
    db  0x9C                            ; PUSHFD (push EFLAGS register)
    db  0xB8, 0x01, 0x00, 0x00, 0x00    ; MOV EAX, 1
    db  0xB8, 0x02, 0x00, 0x00, 0x00    ; MOV EAX, 2
    db  0x8B, 0xD                       ; MOV EDX, EAX
    db  0x83, 0xC2, 0x01                ; ADD EDX, 1
    db  0x83, 0xEA, 0x01                ; SUB EDX, 1
    db  0x9D                            ; POPFQ (pop RFLAGS register)
    db  0x48, 0x89, 0xE5                ; MOV RBP, RSP (set up stack frame)
    db  0x48, 0x8B, 0x45, 0xF8          ; MOV RAX, [RBP-8] (load RDI)
    db  0x48, 0x8B, 0x4D, 0xF0          ; MOV RCX, [RBP-16] (load RSI)
    db  0x48, 0x01, 0xC8                ; ADD RAX, RCX (add RDI and RSI)
    db  0x48, 0x89, 0x45, 0xF8          ; MOV [RBP-8], RAX (store result)
    db  0x48, 0x8B, 0x45, 0xF8          ; MOV RAX, [RBP-8] (load result)
    db  0x48, 0x83, 0xC4, 0x10          ; ADD RSP, 16 (deallocate stack space)
    db  0x5D                            ; POP RBP (restore RBP)
    db  0xCC                            ; INT 3 (breakpoint)
    db  0x90                            ; NOP (no operation)
    db  0xEB, 0xFE                      ; JMP short -2 (infinite loop)
    db  0xC3                             ; RET (return from function)
    db  0x48, 0x83, 0xEC, 0x10          ; SUB RSP, 16 (allocate stack space)
    db  0x48, 0x89, 0x7D, 0xF8          ; MOV [RBP-8], RDI (save RDI)
    db  0x48, 0x89, 0x75, 0xF0          ; MOV [RBP-16], RSI (save RSI)
    db  0x48, 0x8B, 0x45, 0xF8          ; MOV RAX, [RBP-8] (load RDI)
    db  0x48, 0x8B, 0x4D, 0xF0          ; MOV RCX, [RBP-16] (load RSI)
    db  0x48, 0x01, 0xC8                ; ADD RAX, RCX (add RDI and RSI)
    db  0x48, 0x89, 0x45, 0xF8          ; MOV [RBP-8], RAX (store result)
    db  0x48, 0x8B, 0x45, 0xF8          ; MOV RAX, [RBP-8] (load result)
    db  0x48, 0x83, 0xC4, 0x10          ; ADD RSP, 16 (deallocate stack space)
    db  0x5D                            ; POP RBP (restore RBP)
    db  0xCC                            ; INT 3 (breakpoint)
    db  0x90                            ; NOP (no operation)
    db  0xEB, 0xFE                      ; JMP short -2 (infinite loop)
    db  0xC3                            ; RET (return from function)
    db  0x9C                            ; PUSHFD (push EFLAGS register)
    db  0xB8, 0x03, 0x00, 0x00, 0x00    ; MOV EAX, 3
    db  0xBB, 0x04, 0x00, 0x00, 0x00    ; MOV EBX, 4
    db  0x01, 0xD8                      ; ADD EAX, EBX
    db  0x83, 0xC0, 0x01                ; ADD EAX, 1
    db  0x83, 0xE8, 0x01                ; SUB EAX, 1
    db  0x9D                            ; POPFD (pop EFLAGS register)
    db  0xEB, 0xFE                      ; JMP short -2 (infinite loop)
    db  0xC3                            ; RET (return from function)
END
