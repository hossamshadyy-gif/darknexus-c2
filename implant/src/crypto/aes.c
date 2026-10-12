#include "aes.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

/*
 * AES-256-GCM implementation using Windows BCrypt API
 * Compatible with Go's crypto/aes + cipher.NewGCM on the teamserver side
 *
 * Wire format: [12-byte nonce][ciphertext][16-byte auth tag]
 * This matches Go's gcm.Seal(nonce, nonce, plaintext, nil) output
 */

#define GCM_NONCE_SIZE  12
#define GCM_TAG_SIZE    16
#define AES_KEY_SIZE    32

static BYTE hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

BOOL dn_aes_init(BYTE* key_out, const char* hex_key) {
    for (int i = 0; i < AES_KEY_SIZE; i++) {
        key_out[i] = (hex_nibble(hex_key[i * 2]) << 4) | hex_nibble(hex_key[i * 2 + 1]);
    }
    return TRUE;
}

BYTE* dn_aes_encrypt(const BYTE* key, const BYTE* plaintext, DWORD pt_len, DWORD* out_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BYTE* output = NULL;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return NULL;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PBYTE)key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // generate random nonce
    BYTE nonce[GCM_NONCE_SIZE];
    BCryptGenRandom(NULL, nonce, GCM_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // setup auth info
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = GCM_NONCE_SIZE;

    BYTE tag[GCM_TAG_SIZE];
    authInfo.pbTag = tag;
    authInfo.cbTag = GCM_TAG_SIZE;

    // encrypt
    DWORD ct_len = 0;
    status = BCryptEncrypt(hKey, (PBYTE)plaintext, pt_len, &authInfo, NULL, 0, NULL, 0, &ct_len, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // allocate output: nonce + ciphertext + tag
    *out_len = GCM_NONCE_SIZE + ct_len + GCM_TAG_SIZE;
    output = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *out_len);
    if (!output) goto cleanup;

    BYTE* ct_buf = output + GCM_NONCE_SIZE;
    status = BCryptEncrypt(hKey, (PBYTE)plaintext, pt_len, &authInfo, NULL, 0, ct_buf, ct_len, &ct_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, output);
        output = NULL;
        goto cleanup;
    }

    // prepend nonce, append tag
    memcpy(output, nonce, GCM_NONCE_SIZE);
    memcpy(output + GCM_NONCE_SIZE + ct_len, tag, GCM_TAG_SIZE);

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return output;
}

BYTE* dn_aes_decrypt(const BYTE* key, const BYTE* ciphertext, DWORD ct_len, DWORD* out_len) {
    if (ct_len < GCM_NONCE_SIZE + GCM_TAG_SIZE) return NULL;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BYTE* output = NULL;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return NULL;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PBYTE)key, AES_KEY_SIZE, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // extract nonce (first 12 bytes) and tag (last 16 bytes)
    const BYTE* nonce = ciphertext;
    DWORD enc_len = ct_len - GCM_NONCE_SIZE - GCM_TAG_SIZE;
    const BYTE* enc_data = ciphertext + GCM_NONCE_SIZE;
    BYTE tag[GCM_TAG_SIZE];
    memcpy(tag, ciphertext + GCM_NONCE_SIZE + enc_len, GCM_TAG_SIZE);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PBYTE)nonce;
    authInfo.cbNonce = GCM_NONCE_SIZE;
    authInfo.pbTag = tag;
    authInfo.cbTag = GCM_TAG_SIZE;

    *out_len = enc_len;
    output = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, enc_len + 1);
    if (!output) goto cleanup;

    DWORD pt_len = 0;
    status = BCryptDecrypt(hKey, (PBYTE)enc_data, enc_len, &authInfo, NULL, 0, output, enc_len, &pt_len, 0);
    if (!BCRYPT_SUCCESS(status)) {
        HeapFree(GetProcessHeap(), 0, output);
        output = NULL;
        *out_len = 0;
        goto cleanup;
    }
    *out_len = pt_len;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return output;
}
