import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import { EXTENSION_NAME, PACKAGE_ROOT, PROJECT_CONFIG_PATH } from "./consts.ts";
import { userConfigPath } from "./config.ts";
import { pathSurfaceInfo } from "../path-surfaces.ts";
import type { BoundaryRequest } from "../broker/index.ts";

export function isWithin(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

export function protectedWriteHardDeny(
  request: BoundaryRequest,
): { rule: string; reason: string } | undefined {
  const isWrite =
    request.surface === "filesystem-write" ||
    pathSurfaceInfo(request.surface)?.effect === "write" ||
    /\b(?:write|create|delete|rename|chmod|chown)\b/i.test(
      request.operation,
    );
  if (!isWrite) return;
  const target = request.resolvedPath || request.path;
  if (!target) return;
  const resolvedTarget = resolve(request.cwd, target);
  const agentDir = join(homedir(), ".pi", "agent");
  const protectedDirectories = [
    PACKAGE_ROOT,
    join(agentDir, "logs"),
    join(agentDir, "extensions", "pi-auto-review"),
  ];
  const protectedFiles = [
    join(request.cwd, PROJECT_CONFIG_PATH),
    userConfigPath(),
  ];
  if (
    protectedDirectories.some((path) => isWithin(path, resolvedTarget)) ||
    protectedFiles.includes(resolvedTarget)
  ) {
    return {
      rule: "security-control-tampering",
      reason:
        "writing security extension code, policy, configuration, or audit data is forbidden",
    };
  }
}

export function assertTrustedInstallation(
  cwd: string,
  packageRoot = PACKAGE_ROOT,
): void {
  const realCwd = realpathSync(cwd);
  const realPackageRoot = realpathSync(packageRoot);
  if (isWithin(realCwd, realPackageRoot)) {
    throw new Error(
      `${EXTENSION_NAME}: refusing security policy loaded from agent-writable workspace ${realPackageRoot}`,
    );
  }
}


// The reviewer's own config, standing rules, audit data and installed code.
const REVIEWER_PATH =
  /\.pi\/agent\/extensions\/pi-auto-review(?![\w-])|node_modules\/@(?:schuettc|erichll)\/pi-auto-review(?![\w-])/i;
// Shell constructs that write, move, link or delete. Checked per command
// segment, and only where that segment targets a reviewer path.
// Redirects and tee write only to their target, handled separately.
const REDIRECT_TARGET = /(?<![0-9<=-])&?>>?(?![&=>])\s*(\S+)/g;
const TEE_ARGS = /(?:^|[\s(`$])tee\s+((?:-\S+\s+)*)(.+)$/;
const SHELL_WRITES = [
  /(?:^|[\s(`$])(?:sudo\s+)?(?:mv|ln|truncate|rm|rmdir|touch|chmod|chown|unlink)(?=\s|$)/,
  /\b(?:sed|perl)\b[^\n]*\s-[A-Za-z]*i/,
  /\bsqlite3\b[^\n]*\b(?:insert|update|delete|drop|create|replace|vacuum|attach|alter)\b/i,
];
// Copies write only to their destination (the last argument).
const SHELL_COPY = /(?:^|[\s(`$])(?:sudo\s+)?(?:cp|rsync|install|dd)(?=\s|$)/;
// File-writing code (heredocs, -c/-e scripts). Code can hold a path in a
// variable anywhere, so this is checked against the whole command.
const CODE_WRITES = [
  /\bopen\([^)]*,\s*["'][wax]/,
  /\.write(?:_text|_bytes)?\(/,
  /\b(?:write|append)File(?:Sync)?\(|\b(?:rename|copyFile|symlink|unlink|rm|mkdir|cp)Sync\(/,
  /\bshutil\.(?:copy|move|rmtree)|\bos\.(?:rename|replace|remove|unlink|symlink|makedirs|chmod)\(|\bfs\.promises\b/,
];

function lastArgument(segment: string): string {
  const parts = segment.trim().split(/\s+/);
  return parts[parts.length - 1] ?? "";
}

/**
 * Deterministic floor for shell commands that would change the reviewer's
 * config, standing rules, audit data or installed code. protectedWriteHardDeny
 * covers file-tool writes; this covers bash (callers pass the full command, so
 * heredoc bodies count). A shell write counts only when its own segment
 * targets a reviewer path: directly, through a variable assigned one, or after
 * `cd` into one. Reading those files, or copying out of them, passes. An
 * approval or break-glass cannot pass this floor.
 */
export function reviewerTamperingHardDeny(
  command: string | undefined,
): { rule: string; reason: string } | undefined {
  if (!command || !REVIEWER_PATH.test(command)) return;
  const deny = {
    rule: "security-control-tampering",
    reason:
      "changing the permission reviewer's config, rules, audit data or code from a command is forbidden; change them through kempt or /auto-review-rules (reading them is fine, in a separate command from other writes if needed)",
  };
  if (CODE_WRITES.some((pattern) => pattern.test(command))) return deny;
  const vars = new Set<string>();
  const mentions = (text: string) =>
    REVIEWER_PATH.test(text) ||
    [...vars].some((v) => text.includes(`$${v}`) || text.includes(`\${${v}}`));
  let inReviewerDir = false;
  for (const raw of command.split(/\|\||&&|;|\||\n/)) {
    const segment = raw.trim();
    if (!segment) continue;
    for (const m of segment.matchAll(/(?:^|\s)(?:export\s+)?([A-Za-z_]\w*)=(\S+)/g)) {
      if (REVIEWER_PATH.test(m[2]!)) vars.add(m[1]!);
    }
    const cd = segment.match(/^(?:builtin\s+)?(?:cd|pushd)\s+(\S+)/);
    if (cd) inReviewerDir = mentions(cd[1]!);
    if (!inReviewerDir && !mentions(segment)) continue;
    const writesHere = (target: string) =>
      mentions(target) || (inReviewerDir && !/^["']?[\/~$]/.test(target));
    // Quoted text is data, not shell syntax: a ">" inside quotes is not a
    // redirect. A quoted redirect target ("> \"$D/x\"") is kept.
    const unquoted = segment.replace(/(?<!>\s*)(["'])(?:\\.|(?!\1)[^\\])*\1/g, "Q");
    for (const m of unquoted.matchAll(REDIRECT_TARGET)) {
      if (!/^\/dev\/(?:null|stderr|stdout)$/.test(m[1]!) && writesHere(m[1]!)) return deny;
    }
    const tee = segment.match(TEE_ARGS);
    if (tee && tee[2]!.trim().split(/\s+/).some(writesHere)) return deny;
    if (SHELL_WRITES.some((pattern) => pattern.test(segment))) return deny;
    if (SHELL_COPY.test(segment)) {
      if (writesHere(lastArgument(segment))) return deny;
    }
  }
  return undefined;
}
