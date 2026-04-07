import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawn } from "child_process";

/**
 * ALLOWLIST: Only these base commands may be executed inside WSL.
 * Any command not present here is rejected before any process is spawned.
 */
const ALLOWED_COMMANDS = new Set<string>([
  "nmap",
  "ffuf",
  "curl",
  "wget",
  "cat",
  "ls",
  "pwd",
  "whoami",
  "id",
  "uname",
  "echo",
  "find",
  "grep",
  "head",
  "tail",
  "wc",
  "stat",
  "file",
  "dig",
  "host",
  "whois",
  "traceroute",
  "ping",
  "netstat",
  "ss",
  "ip",
  "arp",
  "gobuster",
  "hydra",
  "nikto",
  "sqlmap",
]);

/**
 * INTERACTIVE / HANGING COMMAND BLOCKLIST.
 * These base commands are always blocked because they require a TTY
 * or run indefinitely, which would hang the MCP server process.
 */
const BLOCKED_COMMANDS = new Set<string>([
  "vim",
  "vi",
  "nano",
  "emacs",
  "less",
  "more",
  "top",
  "htop",
  "bash",
  "sh",
  "zsh",
  "fish",
  "ssh",
  "ftp",
  "telnet",
  "nc",
  "netcat",
  "mysql",
  "psql",
]);

/**
 * Explicit scripting/compilation engines blocked to prevent arbitrary code execution.
 */
const BLOCKED_SCRIPTING_ENGINES = new Set<string>([
  "python",
  "python3",
  "perl",
  "ruby",
  "php",
  "node",
  "gcc",
  "g++",
  "bash",
]);

/**
 * DANGEROUS ARGUMENT PATTERNS.
 * These patterns are checked against every argument string.
 * If any argument matches, the request is rejected.
 *
 * This is a defence-in-depth measure on top of shell:false.
 * Even though we never invoke a shell, we block these to prevent
 * abuse of legitimate tools (e.g., curl -o /etc/cron.d/evil).
 */
const DANGEROUS_ARG_PATTERNS: RegExp[] = [
  /[;&|`$<>\\]/,
  /[\r\n\x00]/,
  /^\s*--exec\b/i,
  /^\s*--shell\b/i,
  /\/etc\/(passwd|shadow|sudoers|cron)/i,
  /\/proc\/[0-9]+\/mem/i,
  /^-(o|O)$/,
];

/**
 * Sensitive file-name tokens that should never appear in command/args.
 * We intentionally check exact, substring, and regex-style matches.
 */
const SENSITIVE_TOKENS = [
  "shadow",
  "passwd",
  "sudoers",
  "cron",
  "id_rsa",
  "authorized_keys",
  "bash_history",
  ".env",
  "ssh",
  "var/log",
  "/root",
] as const;

function escapeRegexLiteral(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const SENSITIVE_TOKEN_REGEX = new RegExp(
  `(${SENSITIVE_TOKENS.map((token) => escapeRegexLiteral(token)).join("|")})`,
  "i"
);

const OUTPUT_SYSTEM_PATH_HINT_REGEX =
  /(^|[\s:(])\/(etc|root|var\/log|home|proc|sys|dev|run|usr|opt|bin|sbin)(\/|\b)/i;
const OUTPUT_LS_LONG_LISTING_REGEX = /^[\-dlcbps][rwxstST-]{9}[+@.]?\s+/;

function containsSensitiveToken(value: string): boolean {
  const normalized = value.trim().toLowerCase();

  const exactMatch = SENSITIVE_TOKENS.some((token) => normalized === token);
  if (exactMatch) return true;

  const substringMatch = SENSITIVE_TOKENS.some((token) => normalized.includes(token));
  if (substringMatch) return true;

  return SENSITIVE_TOKEN_REGEX.test(value);
}

function outputLineLooksLikeListing(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed) return false;

  if (OUTPUT_LS_LONG_LISTING_REGEX.test(trimmed)) return true;

  // Handles default ls output where entries are names/columns rather than long-format rows.
  if (/^[A-Za-z0-9._\-\s]+$/.test(trimmed)) return true;

  return false;
}

function outputLineHasSensitiveToken(line: string): boolean {
  const lower = line.toLowerCase();
  return SENSITIVE_TOKENS.some((token) => lower.includes(token)) || SENSITIVE_TOKEN_REGEX.test(line);
}

export function is_sensitive_output(text: string): boolean {
  if (!text) return false;

  const lines = text.split(/\r?\n/);
  let inSystemSection = false;

  for (const line of lines) {
    const trimmed = line.trim();

    if (/^\/(etc|root|var\/log)(\/.*)?:$/.test(trimmed)) {
      inSystemSection = true;
    } else if (/^\/[^\s:]+.*:$/.test(trimmed) && !/^\/(etc|root|var\/log)(\/.*)?:$/.test(trimmed)) {
      inSystemSection = false;
    }

    if (!outputLineHasSensitiveToken(line)) {
      continue;
    }

    const hasSystemPathHint = OUTPUT_SYSTEM_PATH_HINT_REGEX.test(line) || inSystemSection;
    const hasListingHint = outputLineLooksLikeListing(line);

    if (hasSystemPathHint || hasListingHint) {
      return true;
    }
  }

  return false;
}

function scrubSensitiveStdout(text: string): { sanitized: string; redactedLines: number; blocked: boolean } {
  if (!text) {
    return { sanitized: "", redactedLines: 0, blocked: false };
  }

  const lines = text.split(/\r?\n/);
  const safeLines: string[] = [];
  let redactedLines = 0;
  let inSystemSection = false;

  for (const line of lines) {
    const trimmed = line.trim();

    if (/^\/(etc|root|var\/log)(\/.*)?:$/.test(trimmed)) {
      inSystemSection = true;
    } else if (/^\/[^\s:]+.*:$/.test(trimmed) && !/^\/(etc|root|var\/log)(\/.*)?:$/.test(trimmed)) {
      inSystemSection = false;
    }

    const hasToken = outputLineHasSensitiveToken(line);
    const hasSystemPathHint = OUTPUT_SYSTEM_PATH_HINT_REGEX.test(line) || inSystemSection;
    const hasListingHint = outputLineLooksLikeListing(line);

    if (hasToken && (hasSystemPathHint || hasListingHint)) {
      redactedLines += 1;
      continue;
    }

    safeLines.push(line);
  }

  const sanitized = safeLines.join("\n");
  const blocked = redactedLines > 0 && sanitized.trim().length === 0;

  return { sanitized, redactedLines, blocked };
}

function isPingSafe(args: string[]): boolean {
  const hasCFlag = args.some(
    (a, i) =>
      (a === "-c" || a === "--count") && i + 1 < args.length
  );
  const hasCombined = args.some((a) => /^-c\d+$/.test(a));
  return hasCFlag || hasCombined;
}

const EXECUTION_TIMEOUT_MS = 60_000; // 60 seconds
const MAX_OUTPUT_BYTES = 512_000; // 512 KB
const WSL_EXECUTABLE = "C:\\Windows\\System32\\wsl.exe";

interface WslResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  timedOut: boolean;
  truncated: boolean;
}

function runInWsl(command: string, args: string[]): Promise<WslResult> {
  return new Promise((resolve) => {
    /**
     * We call:  wsl.exe -- <command> [args...]
     *
     * The "--" separator tells wsl.exe that everything that follows is
     * the Linux command line and should NOT be interpreted by wsl.exe
     * itself, preventing any wsl.exe flag injection via the command name.
     *
     * shell: false  (the default) means Node.js does NOT wrap this in
     * cmd.exe or /bin/sh, so metacharacters in args are completely inert.
     */
    const wslArgs = ["--", command, ...args];

    const child = spawn(WSL_EXECUTABLE, wslArgs, {
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdoutBuf = "";
    let stderrBuf = "";
    let totalBytes = 0;
    let truncated = false;
    let timedOut = false;

    const killTimer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, EXECUTION_TIMEOUT_MS);

    child.stdout.on("data", (chunk: Buffer) => {
      const remaining = MAX_OUTPUT_BYTES - totalBytes;
      if (remaining <= 0) {
        truncated = true;
        return;
      }
      const slice = chunk.slice(0, remaining);
      stdoutBuf += slice.toString("utf8");
      totalBytes += slice.length;
    });

    child.stderr.on("data", (chunk: Buffer) => {
      const remaining = MAX_OUTPUT_BYTES - totalBytes;
      if (remaining <= 0) {
        truncated = true;
        return;
      }
      const slice = chunk.slice(0, remaining);
      stderrBuf += slice.toString("utf8");
      totalBytes += slice.length;
    });

    child.on("close", (exitCode) => {
      clearTimeout(killTimer);
      resolve({
        stdout: stdoutBuf,
        stderr: stderrBuf,
        exitCode,
        timedOut,
        truncated,
      });
    });

    child.on("error", (err) => {
      clearTimeout(killTimer);
      resolve({
        stdout: "",
        stderr: `Failed to spawn wsl.exe: ${err.message}`,
        exitCode: -1,
        timedOut: false,
        truncated: false,
      });
    });
  });
}

const server = new McpServer({
  name: "wsl-mcp-server",
  version: "1.0.0",
});

server.tool(
  "run_wsl_command",

  `Execute an allowlisted command inside Windows Subsystem for Linux (WSL).

Allowed commands: ${[...ALLOWED_COMMANDS].join(", ")}

Security constraints:
- Only the listed commands are permitted.
- Scripting engines/compilers (python, node, perl, ruby, php, gcc/g++, bash) are blocked.
- Arguments are passed directly to the process (no shell interpretation).
- Interactive commands (vim, top, bare python REPL, etc.) are blocked.
- ping requires a -c <count> flag (e.g. -c 4) to prevent infinite execution.
- Sensitive file-listing output is scrubbed from STDOUT before being returned.
- Execution is killed after ${EXECUTION_TIMEOUT_MS / 1000} seconds.
- Output is capped at ${MAX_OUTPUT_BYTES / 1024} KB.`,

  {
    command: z
      .string()
      .min(1)
      .max(64)
      .describe("The base command to run inside WSL (e.g. ls, curl, nmap)"),
    args: z
      .array(z.string().max(1024))
      .max(64)
      .default([])
      .describe("Arguments for the command. Each element is one argument."),
  },

  async ({ command, args }) => {
    const cmd = command.trim().toLowerCase();

    if (BLOCKED_SCRIPTING_ENGINES.has(cmd)) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `[SECURITY] Command \"${cmd}\" is blocked because scripting/compilation engines are not allowed.`,
          },
        ],
      };
    }

    if (containsSensitiveToken(command)) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `[SECURITY] Command \"${command}\" contains a forbidden sensitive token.`,
          },
        ],
      };
    }

    for (let i = 0; i < args.length; i++) {
      const arg = args[i];
      if (containsSensitiveToken(arg)) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `[SECURITY] Argument at index ${i} (\"${arg}\") contains a forbidden sensitive token.`,
            },
          ],
        };
      }
    }

    if (BLOCKED_COMMANDS.has(cmd)) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `[SECURITY] Command "${cmd}" is blocked because it is interactive or dangerous.`,
          },
        ],
      };
    }

    if (!ALLOWED_COMMANDS.has(cmd)) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text:
              `[SECURITY] Command "${cmd}" is not on the allowlist.\n` +
              `Permitted commands: ${[...ALLOWED_COMMANDS].join(", ")}`,
          },
        ],
      };
    }

    for (const arg of args) {
      for (const pattern of DANGEROUS_ARG_PATTERNS) {
        if (pattern.test(arg)) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: `[SECURITY] Argument "${arg}" contains a forbidden pattern (${pattern}).`,
              },
            ],
          };
        }
      }
    }

    if (cmd === "ping" && !isPingSafe(args)) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: "[SECURITY] ping requires a -c <count> flag (e.g. -c 4) to prevent infinite execution.",
          },
        ],
      };
    }

    const result = await runInWsl(cmd, args);

    const stdoutIsSensitive = is_sensitive_output(result.stdout);
    const scrubbedStdout = scrubSensitiveStdout(result.stdout);
    const sanitizedStdoutStillSensitive = is_sensitive_output(scrubbedStdout.sanitized);

    if (stdoutIsSensitive || sanitizedStdoutStillSensitive) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text:
              "[SECURITY] Sensitive output detected in STDOUT. Response blocked to prevent information leakage." +
              (scrubbedStdout.redactedLines > 0
                ? ` Redacted candidate lines: ${scrubbedStdout.redactedLines}.`
                : ""),
          },
        ],
      };
    }

    const lines: string[] = [];

    if (result.timedOut) {
      lines.push(`[TIMEOUT] Process killed after ${EXECUTION_TIMEOUT_MS / 1000}s.`);
    }

    if (result.truncated) {
      lines.push(`[TRUNCATED] Output exceeded ${MAX_OUTPUT_BYTES / 1024} KB limit.`);
    }

    if (scrubbedStdout.redactedLines > 0) {
      lines.push(`[REDACTED] Removed ${scrubbedStdout.redactedLines} sensitive line(s) from STDOUT.`);
    }

    if (scrubbedStdout.blocked) {
      lines.push("[SECURITY] STDOUT was fully redacted because it only contained sensitive listing/path data.");
    }

    lines.push(`[EXIT CODE] ${result.exitCode ?? "unknown"}`);

    if (scrubbedStdout.sanitized) {
      lines.push("--- STDOUT ---");
      lines.push(scrubbedStdout.sanitized);
    }

    if (result.stderr) {
      lines.push("--- STDERR ---");
      lines.push(result.stderr);
    }

    if (!scrubbedStdout.sanitized && !result.stderr) {
      lines.push("(no output)");
    }

    return {
      isError: result.timedOut || (result.exitCode !== 0 && result.exitCode !== null),
      content: [
        {
          type: "text",
          text: lines.join("\n"),
        },
      ],
    };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("WSL MCP Server running on stdio transport.\n");
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err}\n`);
  process.exit(1);
});
