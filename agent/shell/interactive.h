// SPDX-License-Identifier: MIT License - Copyright (c) 2026 Nicholas Starke

#ifndef SHELL_INTERACTIVE_H
#define SHELL_INTERACTIVE_H

/* Parse a shell-like line into an argv/argc array. Returns 0 on success,
 * -1 on allocation failure, 2 on parse error. */
int interactive_parse_line(const char *line, char ***argv_out, int *argc_out);

/* Free an argv array previously returned by interactive_parse_line. */
void interactive_free_argv(char **argv, int argc);

/* Handle the interactive "set" built-in. */
int interactive_set_command(int argc, char **argv);

/* Run the interactive REPL loop. Returns the exit code. */
int interactive_loop(const char *prog);

#endif /* SHELL_INTERACTIVE_H */
