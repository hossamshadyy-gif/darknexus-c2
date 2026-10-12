#ifndef DN_AES_H
#define DN_AES_H

#include <windows.h>

/*
 * AES-256-GCM encryption using Windows BCrypt API
 * No external dependencies, no CRT crypto needed
 */

// Initialize AES context from hex-encoded PSK
BOOL dn_aes_init(BYTE* key_out, const char* hex_key);

// Encrypt plaintext with AES-256-GCM
// Returns allocated buffer: [12-byte nonce][ciphertext][16-byte tag]
// Caller must free with HeapFree
BYTE* dn_aes_encrypt(const BYTE* key, const BYTE* plaintext, DWORD pt_len, DWORD* out_len);

// Decrypt AES-256-GCM ciphertext
// Input format: [12-byte nonce][ciphertext][16-byte tag]
// Returns allocated buffer with plaintext
// Caller must free with HeapFree
BYTE* dn_aes_decrypt(const BYTE* key, const BYTE* ciphertext, DWORD ct_len, DWORD* out_len);

#endif // DN_AES_H
