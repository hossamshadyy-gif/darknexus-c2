#ifndef DN_PEB_TYPES_H
#define DN_PEB_TYPES_H

#include <windows.h>

/*
 * Dark Nexus - Custom PEB/LDR Structures
 *
 * mingw-w64's winternl.h defines incomplete PEB and LDR_DATA_TABLE_ENTRY
 * structs (missing InLoadOrderModuleList, BaseDllName, DllBase, etc.)
 * We define our own versions with the fields we actually need for
 * PEB-walking API resolution.
 *
 * These match the real Windows internal structures at the offsets
 * that matter for x64 and x86.
 */

// Prevent winternl.h from conflicting if included after us
#ifdef _PEB_LDR_DATA
#undef _PEB_LDR_DATA
#endif

// Our UNICODE_STRING (matches ntdef.h layout)
typedef struct _DN_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} DN_UNICODE_STRING, *PDN_UNICODE_STRING;

// LDR_DATA_TABLE_ENTRY with the fields we need
typedef struct _DN_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    DN_UNICODE_STRING FullDllName;
    DN_UNICODE_STRING BaseDllName;
    // ... more fields follow, but we only need up to BaseDllName
} DN_LDR_DATA_TABLE_ENTRY, *PDN_LDR_DATA_TABLE_ENTRY;

// PEB_LDR_DATA with InLoadOrderModuleList
typedef struct _DN_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} DN_PEB_LDR_DATA, *PDN_PEB_LDR_DATA;

// Minimal PEB with the fields we need
typedef struct _DN_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
#ifdef _WIN64
    BYTE Padding0[4];
#endif
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PDN_PEB_LDR_DATA Ldr;
    // ... more fields follow
} DN_PEB, *PDN_PEB;

// Helper: get PEB pointer via segment register
static inline PDN_PEB dn_get_peb(void) {
#ifdef _WIN64
    return (PDN_PEB)__readgsqword(0x60);
#else
    return (PDN_PEB)__readfsdword(0x30);
#endif
}

// -------------------------------------------------------------------
// NT types that mingw-w64 winternl.h doesn't expose
// -------------------------------------------------------------------

// OBJECT_ATTRIBUTES (used by NtOpenSection, etc.)
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040
#endif

typedef struct _DN_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    DN_UNICODE_STRING* ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} DN_OBJECT_ATTRIBUTES, *PDN_OBJECT_ATTRIBUTES;

#define DN_InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(DN_OBJECT_ATTRIBUTES);         \
    (p)->RootDirectory = r;                             \
    (p)->ObjectName = n;                                \
    (p)->Attributes = a;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
}

#endif // DN_PEB_TYPES_H
