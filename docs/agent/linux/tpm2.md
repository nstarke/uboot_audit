# `embedded_linux_audit linux tpm2` Command

Runs a fixed set of TPM2 commands through the TPM2-TSS library instead of shelling out to `tpm2_*` executables.

```bash
embedded_linux_audit linux tpm2 <command> [args]
```

## Supported commands

- `list-commands` — print the built-in TPM2 commands compiled into `embedded_linux_audit`
- `getcap <properties-fixed|properties-variable|algorithms|commands|pcrs>` — query TPM capabilities
- `pcrread <alg:pcr[,pcr...]> [alg:pcr[,pcr...]]...` — read PCR values
- `nvreadpublic <nv-index>` — read public NV index metadata
- `createprimary [-C <o|p|e|n>] [-g <sha1|sha256|sha384|sha512>] [-G <rsa|ecc>] [-c <context-file>]` — create a primary object

## Notes

- `list-commands` is static now; it no longer scans `PATH`.
- `embedded_linux_audit linux tpm2` no longer depends on installed `tpm2-tools` binaries.
- `createprimary -c` writes an ESYS-serialized handle for this tool, not a `tpm2-tools` context file.
- `--output-format`, `--output-tcp`, and `--output-http` do not transform TPM2 output.

## Examples

```bash
./embedded_linux_audit linux tpm2 list-commands
./embedded_linux_audit linux tpm2 getcap properties-fixed
./embedded_linux_audit linux tpm2 pcrread sha256:0,1,2
./embedded_linux_audit linux tpm2 nvreadpublic 0x1500016
./embedded_linux_audit linux tpm2 createprimary -C o -g sha256 -G rsa -c primary.ctx
```
