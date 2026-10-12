#include "strings_encrypt.h"
#include "strings_table.h"

/*
 * Dark Nexus - String Decryption Runtime
 *
 * Decrypts XOR-encrypted strings from the build-time generated
 * table into a caller-owned buffer. The caller is responsible
 * for zeroing the buffer after use (SecureZeroMemory).
 *
 * The decryption is trivial by design: XOR with a repeating
 * 16-byte key. The goal is not cryptographic strength but
 * defeating static string scanning. Any runtime debugger can
 * still see the decrypted strings in memory, but signature
 * scanners that only examine the PE on disk will see nothing.
 */

char* dn_decrypt_string(int string_id, char* buf, int buf_size) {
    if (string_id < 0 || string_id >= DN_STR_COUNT)
        return NULL;

    int str_len = g_enc_lengths[string_id];

    // need room for the string + null terminator
    if (buf_size < str_len + 1)
        return NULL;

    const unsigned char* enc = g_enc_strings[string_id];

    for (int i = 0; i < str_len; i++) {
        buf[i] = (char)(enc[i] ^ DN_STR_KEY[i % 16]);
    }
    buf[str_len] = '\0';

    return buf;
}

wchar_t* dn_decrypt_wstring(int string_id, wchar_t* buf, int buf_size) {
    if (string_id < 0 || string_id >= DN_STR_COUNT)
        return NULL;

    int str_len = g_enc_lengths[string_id];

    // buf_size is in wchar_t units, need room for string + null
    if (buf_size < str_len + 1)
        return NULL;

    const unsigned char* enc = g_enc_strings[string_id];

    for (int i = 0; i < str_len; i++) {
        buf[i] = (wchar_t)(enc[i] ^ DN_STR_KEY[i % 16]);
    }
    buf[str_len] = L'\0';

    return buf;
}
