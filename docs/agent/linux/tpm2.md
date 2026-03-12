# `embedded_linux_audit linux tpm2` Command

Runs TPM2 commands through the host's installed `tpm2-tools` style executables using a generic wrapper. Any executable named `tpm2_<command>` on `PATH` becomes available as:

```bash
embedded_linux_audit linux tpm2 <command> [...args]
```

For example, if `tpm2_getcap` and `tpm2_pcrread` are installed, you can invoke them as:

```bash
embedded_linux_audit linux tpm2 getcap properties-fixed
embedded_linux_audit linux tpm2 pcrread sha256:0,1,2
```

The repository vendors `TPM2-TSS` as a submodule under `third_party/tpm2-tss`, while the runtime wrapper delegates actual command execution to the system's `tpm2_*` command-line tools.

## Arguments

- `<command>` — required TPM2 subcommand name, mapped to `tpm2_<command>`
- `[...args]` — all remaining arguments are passed through unchanged to the delegated `tpm2_<command>` executable
- `list-commands` — special helper that scans `PATH` and prints discovered `tpm2_*` executables without the `tpm2_` prefix

## Notes

- This wrapper is intentionally generic, so it supports the full installed `tpm2-tools` command set instead of hard-coding a fixed TPM2 command list.
- `--output-format`, `--output-tcp`, and `--output-http` do not transform TPM2 output; stdout/stderr behavior is controlled by the delegated `tpm2_*` tool.
- If the requested TPM2 command is not installed, the wrapper returns exit status `127`.

## Examples

```bash
./embedded_linux_audit linux tpm2 list-commands
./embedded_linux_audit linux tpm2 getcap properties-fixed
./embedded_linux_audit linux tpm2 pcrread sha256:0,1,2
./embedded_linux_audit linux tpm2 createprimary -C o -g sha256 -G rsa -c primary.ctx
```