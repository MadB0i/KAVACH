// Kavach pre-execution hook for OpenCode (`tool.execute.before`).
//
// Wiring: add this file's path to the `plugin` array in opencode.json
// (global ~/.config/opencode/opencode.json or project .opencode/), e.g.
//   { "plugin": ["C:/Kavach/adapters/opencode/kavach-hook.mjs"] }
// or let `kavach setup` do it. Shape mirrors the proven KavachBench
// adapter: map tool -> ToolRequest -> `kavach policy explain --json
// --feed-log` -> throw to block (fail closed).
//
// Env: KAVACH_BIN (default "kavach"), KAVACH_POLICY (required),
// KAVACH_FEED_LOG (optional, feeds kavach-dashboard).

import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFileSync, unlinkSync } from "node:fs";

const KAVACH_BIN = process.env.KAVACH_BIN || "kavach";
const KAVACH_POLICY = process.env.KAVACH_POLICY || "";
const KAVACH_FEED_LOG = process.env.KAVACH_FEED_LOG || "";

const BASH_TOOLS = new Set(["bash"]);
const WRITE_TOOLS = new Set(["write"]);
const EDIT_TOOLS = new Set(["edit"]);
const READ_TOOLS = new Set(["read", "glob", "grep"]);
const ALLOW_TOOLS = new Set(["todowrite", "task", "skill", "webfetch", "websearch"]);

function splitCommand(command) {
  const parts = [];
  let current = "";
  let inSingle = false, inDouble = false, escaped = false;
  for (const ch of command) {
    if (escaped) { current += ch; escaped = false; continue; }
    if (ch === "\\") { escaped = true; continue; }
    if (ch === "'" && !inDouble) { inSingle = !inSingle; continue; }
    if (ch === '"' && !inSingle) { inDouble = !inDouble; continue; }
    if (ch === " " && !inSingle && !inDouble) {
      if (current) { parts.push(current); current = ""; }
      continue;
    }
    current += ch;
  }
  if (current) parts.push(current);
  return [parts[0] || "", parts.slice(1)];
}

function mapToolToKavach(toolName, args) {
  if (BASH_TOOLS.has(toolName)) {
    const command = (args?.command) || "";
    if (!command.trim()) return null;
    const [executable, arguments_] = splitCommand(command);
    return [{ command_execute: null }, { Command: { executable, arguments: arguments_ } }];
  }
  const path = (args?.filePath || args?.path || "").replace(/\\/g, "/");
  if (!path) return null;
  if (WRITE_TOOLS.has(toolName)) return [{ file_create: null }, { File: { path } }];
  if (EDIT_TOOLS.has(toolName)) return [{ file_write: null }, { File: { path } }];
  if (READ_TOOLS.has(toolName)) return [{ file_read: {} }, { File: { path } }];
  return null;
}

function runKavach(operation, resource, sessionID) {
  const request = {
    request_id: `kavach-hook-${Date.now()}`,
    subject: {
      agent_id: "opencode", session_id: sessionID || "hook-session",
      display_name: "OpenCode (Kavach hook)", trust_level: "standard",
      declared_capabilities: [],
    },
    operation, resource,
    context: {
      timestamp: { secs_since_epoch: 0, nanos_since_epoch: 0 },
      working_directory: process.cwd().replace(/\\/g, "/"),
      declared_intent: "Agent tool call (Kavach hook)",
      parent_request_id: null, metadata: {}, dry_run: false,
    },
  };
  const tmpPath = join(tmpdir(), `kavach-req-${Date.now()}.json`);
  try {
    writeFileSync(tmpPath, JSON.stringify(request), "utf-8");
    const argv = ["policy", "explain", "--policy", KAVACH_POLICY,
      "--request", tmpPath, "--json"];
    if (KAVACH_FEED_LOG) argv.push("--feed-log", KAVACH_FEED_LOG);
    const stdout = execFileSync(KAVACH_BIN, argv,
      { encoding: "utf-8", timeout: 10_000 });
    const decision = JSON.parse(stdout);
    return { effect: decision.effect ?? null, reason: decision.explanation ?? "" };
  } catch {
    return { effect: null, reason: "" };
  } finally {
    try { unlinkSync(tmpPath); } catch { /* ignore */ }
  }
}

export const KavachPlugin = async () => ({
  "tool.execute.before": async (input, output) => {
    if (ALLOW_TOOLS.has(input.tool)) return;
    if (!KAVACH_POLICY) {
      throw new Error("Kavach: KAVACH_POLICY not set; failing closed (deny)");
    }
    const mapped = mapToolToKavach(input.tool, output.args);
    if (mapped === null) {
      throw new Error(`Kavach: blocked tool '${input.tool}' — not mapped to a Kavach policy subject`);
    }
    const { effect, reason } = runKavach(mapped[0], mapped[1], input.sessionID);
    if (effect === "Allow") return;
    if (effect === "RequireApproval") {
      throw new Error("Kavach: RequireApproval treated as Deny (no interactive path in v1)");
    }
    throw new Error(`Kavach: blocked by policy — ${reason || effect || "check failed"}`);
  },
});
