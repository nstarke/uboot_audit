# `embedded_linux_audit --script` Feature

The top-level `--script` option runs commands from a file instead of requiring a single command on the CLI.

This is useful when you want to:

- batch multiple `embedded_linux_audit` commands together
- reuse the same collection workflow across systems
- host a script remotely and fetch it over HTTP(S)
- combine scripted execution with wrapper-level options such as `--output-format`, `--output-http`, `--output-tcp`, `--quiet`, and `--insecure`

## Usage

```bash
./embedded_linux_audit --script <path>
./embedded_linux_audit --script http://host/path/commands.txt
./embedded_linux_audit --script https://host/path/commands.txt
```

You can also use the environment variable `ELA_SCRIPT` as the default script source:

```bash
ELA_SCRIPT=./commands.txt ./embedded_linux_audit
```

In interactive mode, `set ELA_SCRIPT <path|url>` sets the same default for the current process.

## Script file format

Each non-empty line is parsed as one command.

- blank lines are ignored
- lines beginning with `#` are treated as comments
- quoting follows the same parser used by interactive mode
- each line may optionally begin with `ela` or `embedded_linux_audit`

Each parsed line must resolve to a normal command sequence such as:

```text
linux dmesg
linux execute-command "uname -a"
linux list-files /etc --recursive
uboot env
embedded_linux_audit linux execute-command "printf hello"
```

## Remote scripts

If the `--script` value starts with `http://` or `https://`, the script is first downloaded to a temporary file and then executed line by line.

- `https://` downloads use the embedded CA bundle by default
- `--insecure` disables TLS certificate and hostname verification for HTTPS script downloads

## Behavior and constraints

- Use `--script` by itself instead of mixing it with a direct command.
- If both a script and a direct command are provided, the wrapper exits with an error.
- Commands run in order, one line at a time.
- Execution stops on the first failing script line and returns that line's command status.
- Wrapper-level options are applied before script execution starts, so they affect all commands in the script.

For example, this applies JSON formatting and HTTP output to every command in the script:

```bash
./embedded_linux_audit --output-format json \
  --output-http http://127.0.0.1:5000/upload \
  --script ./commands.txt
```

## Examples

Example script file:

```text
# Collect a few Linux details
linux execute-command "uname -a"
linux execute-command "id"
linux list-files /etc
```

Run it locally:

```bash
./embedded_linux_audit --script ./commands.txt
```

Run the same script from a helper server over HTTPS:

```bash
./embedded_linux_audit --insecure \
  --output-format json \
  --output-http https://127.0.0.1:5443 \
  --script https://127.0.0.1/tests/scripts/sample-script.txt
```