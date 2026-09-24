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
// Shell and code constructs that write, move, link or delete files. A
// command that mentions a reviewer path AND contains one of these is treated
// as tampering, even if the write target is spelled indirectly ($D/…, cd
// then a relative name). Reads (cat, jq, sed -n, grep, sqlite3 SELECT) pass.
const WRITE_CONSTRUCTS = [
  /(?<![0-9&>=<-])>>?(?![&=>])\s*(?!\/dev\/(?:null|stderr|stdout)\b)/,
  /&>>?\s*(?!\/dev\/null\b)/,
  /(?:^|[\s;&|(`$])(?:sudo\s+)?(?:tee|cp|mv|ln|install|rsync|dd|truncate|rm|rmdir|touch|chmod|chown|unlink)(?=\s|$)/,
  /\b(?:sed|perl)\b[^\n;|&]*\s-[A-Za-z]*i/,
  /\bsqlite3\b[^\n]*\b(?:insert|update|delete|drop|create|replace|vacuum|attach|alter)\b/i,
  /\bopen\([^)]*,\s*["'][wax]/,
  /\.write(?:_text|_bytes)?\(/,
  /\b(?:write|append)File(?:Sync)?\(|\b(?:rename|copyFile|symlink|unlink|rm|mkdir|cp)Sync\(/,
  /\bshutil\.|\bos\.(?:rename|replace|remove|unlink|symlink|makedirs|chmod)\(|\bfs\.promises\b/,
];

/**
 * Deterministic floor for shell commands that would change the reviewer's
 * config, standing rules, audit data or installed code. protectedWriteHardDeny
 * covers file-tool writes; this covers bash (including heredoc bodies, so
 * callers pass the full command). An approval or break-glass cannot pass it;
 * the human changes these files outside pi (kempt, /auto-review-rules).
 */
export function reviewerTamperingHardDeny(
  command: string | undefined,
): { rule: string; reason: string } | undefined {
  if (!command || !REVIEWER_PATH.test(command)) return;
  if (!WRITE_CONSTRUCTS.some((pattern) => pattern.test(command))) return;
  return {
    rule: "security-control-tampering",
    reason:
      "changing the permission reviewer's config, rules, audit data or code from a command is forbidden",
  };
}
