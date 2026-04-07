# WSL MCP Server

Secure Model Context Protocol (MCP) server that runs a tightly controlled set of Linux commands through WSL.

This server is designed for AI-assisted security workflows where command execution is useful, but data leakage and arbitrary code execution must be aggressively blocked.

## What This MCP Does

It exposes one MCP tool:

- `run_wsl_command`

The tool lets an MCP client request command execution in WSL with strict controls:

- Only approved base commands can run.
- High-risk engines (interpreters/compilers) are explicitly denied.
- Arguments are deep-inspected for sensitive targets and dangerous patterns.
- Output is inspected before being returned; sensitive output is blocked.
- Processes are bounded by timeout and output-size limits.

## Core Capabilities

### 1. Controlled Command Execution in WSL

- Uses `wsl.exe -- <command> [args...]`.
- Uses `child_process.spawn` with `shell: false`.
- Closes stdin to avoid interactive hangs.

### 2. Command Allowlist

Permitted base commands:

- `nmap`, `ffuf`, `curl`, `wget`, `cat`, `ls`, `pwd`, `whoami`, `id`, `uname`, `echo`, `find`, `grep`, `head`, `tail`, `wc`, `stat`, `file`, `dig`, `host`, `whois`, `traceroute`, `ping`, `netstat`, `ss`, `ip`, `arp`, `gobuster`, `hydra`, `nikto`, `sqlmap`

If a command is not in the allowlist, the request is rejected.

### 3. Explicit Engine Blocking (Anti-Bypass)

Even before allowlist processing, these base commands are explicitly blocked:

- `python`, `python3`, `perl`, `ruby`, `php`, `node`, `gcc`, `g++`, `bash`

This prevents script-based and compiler-based bypasses.

### 4. Interactive/Hanging Command Blocking

Known interactive or hanging commands are blocked (for example `vim`, `top`, `ssh`, `mysql`, `psql`, `sh`, `zsh`).

### 5. Deep Input Inspection

Both the base `command` and every entry in `args` are inspected with exact/substring/regex matching against sensitive tokens.

Current sensitive dictionary:

- `shadow`, `passwd`, `sudoers`, `cron`, `id_rsa`, `authorized_keys`, `bash_history`, `.env`, `ssh`, `var/log`, `/root`

Dangerous argument patterns are also blocked (for example shell metacharacters, null bytes, exec/shell style flags, and selected sensitive path patterns).

### 6. Output Scrubber and Leak Prevention

STDOUT is analyzed with contextual detection logic:

- Sensitive keywords
- System-path hints (for example `/etc`, `/root`, `/var/log`)
- Listing-style lines (for example `ls -l` permission rows)

If sensitive output is detected, the response is blocked to prevent information leakage.

### 7. Runtime Safety Limits

- Timeout: 60 seconds per command
- Output cap: 512 KB combined stdout/stderr
- Truncation and timeout status are reported in the tool response

## Tool Contract

### Tool Name

- `run_wsl_command`

### Input

```json
{
  "command": "ls",
  "args": ["-la", "/tmp"]
}
```

Rules:

- `command`: non-empty string, max 64 chars
- `args`: array of strings, max 64 args, each arg max 1024 chars

### Output

Text response with status sections such as:

- `[EXIT CODE]`
- `--- STDOUT ---`
- `--- STDERR ---`
- `[TIMEOUT]`
- `[TRUNCATED]`
- Security errors prefixed with `[SECURITY]`

## Setup

### 1. Install dependencies

```powershell
npm install
```

### 2. Build

```powershell
npm run build
```

### 3. Quick local check

```powershell
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | node dist/index.js
```

## MCP Client Configuration Example

For Claude Desktop, edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wsl-runner": {
      "command": "node",
      "args": ["C:\\full\\path\\to\\wsl-mcp-server\\dist\\index.js"]
    }
  }
}
```

Restart the client after changes.

## Security Notes

- This server is intentionally restrictive.
- The policy is deny-by-default: unknown commands and risky patterns are rejected.
- If you expand capabilities, keep protections aligned across input validation and output filtering.
