// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#ifndef SHELL_SCRIPT_EXEC_H
#define SHELL_SCRIPT_EXEC_H

/* Execute commands from a local or remote script file.
 * prog is argv[0] (program name); script_source is the path or URL.
 * Returns 0 on success, 2 on error. */
int execute_script_commands(const char *prog, const char *script_source);

#endif /* SHELL_SCRIPT_EXEC_H */
