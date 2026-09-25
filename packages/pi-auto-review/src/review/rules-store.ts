// Standing authorization rules the human adds from inside pi with
// /auto-review-rules. They live next to the kempt-managed user config, in
// <pi agent dir>/extensions/pi-auto-review/rules.json, so a `kempt update`
// never overwrites them. Every rule is stored there, including Project rules:
// a rules file inside a repository would be writable by the agent working in
// it. That directory is a protected write target (review/guards.ts), and the
// panel saves only after a confirmation typed in the TUI, so an agent cannot
// add or enable a rule for itself.
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { scopeCovers, userConfigPath } from "./config.ts";

export type RuleScope = "user" | "project";

export type LocalRule = {
  id: string;
  rule: string;
  /** user: every project on this machine; project: one git repository. */
  scope: RuleScope;
  /** Project root (the main checkout, so every worktree matches). */
  project?: string;
  enabled: boolean;
  /** ISO time the human added (or last edited) the rule. */
  addedAt: string;
  /** Session the rule was added from, for the panel's history line. */
  session?: string;
};

export const MAX_RULE_CHARACTERS = 1_000;

export function rulesPath(): string {
  return join(dirname(userConfigPath()), "rules.json");
}

export function validateRule(rule: string): string | undefined {
  if (!rule.trim()) return "the rule is empty";
  if (rule.length > MAX_RULE_CHARACTERS) return `the rule is longer than ${MAX_RULE_CHARACTERS} characters`;
  if (/[\u0000-\u001f]/.test(rule)) return "the rule contains a control character";
  return undefined;
}

const projectRoots = new Map<string, string | undefined>();

/**
 * The git repository a directory belongs to, as the main checkout's root, so
 * a linked worktree (a `.git` file pointing into <repo>/.git/worktrees/<name>)
 * maps to the same project as the main checkout. Undefined outside a repo.
 */
export function projectRootFor(cwd: string): string | undefined {
  const start = resolve(cwd);
  if (projectRoots.has(start)) return projectRoots.get(start);
  let root: string | undefined;
  for (let dir = start; ; dir = dirname(dir)) {
    const dotGit = join(dir, ".git");
    try {
      const st = statSync(dotGit);
      if (st.isDirectory()) {
        root = realpathSync(dir);
      } else if (st.isFile()) {
        const gitdir = readFileSync(dotGit, "utf8").match(/^gitdir:\s*(.+)$/m)?.[1]?.trim();
        const linked = gitdir ? resolve(dir, gitdir) : undefined;
        const marker = `${sep}worktrees${sep}`;
        // Trust the link only if the main repository links back: git writes
        // <common>/worktrees/<name>/gitdir pointing at this .git file. A
        // planted .git file cannot borrow another repository's rules.
        let linkedBack = false;
        if (linked && linked.includes(marker)) {
          try {
            linkedBack = realpathSync(readFileSync(join(linked, "gitdir"), "utf8").trim()) === realpathSync(dotGit);
          } catch { linkedBack = false; }
        }
        if (linked && linkedBack) {
          const common = linked.slice(0, linked.lastIndexOf(marker));
          root = realpathSync(basename(common) === ".git" ? dirname(common) : common);
        } else {
          root = realpathSync(dir);
        }
      }
    } catch {
      // not here: keep walking up
    }
    if (root !== undefined || dirname(dir) === dir) break;
  }
  projectRoots.set(start, root);
  return root;
}

/** Whether a stored rule applies to a request made from cwd. */
export function ruleApplies(rule: LocalRule, cwd: string): boolean {
  if (!rule.enabled) return false;
  if (rule.scope === "user") return true;
  if (!rule.project) return false;
  return scopeCovers(rule.project, cwd) || projectRootFor(cwd) === rule.project;
}

/** The text of the enabled rules that apply to a request made from cwd. */
export function localRulesFor(rules: readonly LocalRule[], cwd: string): string[] {
  return rules.filter((rule) => ruleApplies(rule, cwd)).map((rule) => rule.rule);
}

function expandHome(path: string, home: string): string {
  return path === "~" ? home : path.startsWith("~/") ? join(home, path.slice(2)) : path;
}

export class RulesStore {
  readonly path: string;
  #cache: { stamp: string; result: { rules: LocalRule[]; problem?: string } } | undefined;

  constructor(options: { path?: string } = {}) {
    this.path = options.path ?? rulesPath();
  }

  /**
   * Never throws: a missing or unreadable file means no local rules (fail
   * safe). Reparses only when the file's mtime or size changes, since this
   * runs on every review.
   */
  load(): { rules: LocalRule[]; problem?: string } {
    let stamp = "missing";
    try {
      const st = statSync(this.path);
      stamp = `${st.mtimeMs}:${st.size}`;
    } catch { /* missing: #read reports it */ }
    if (this.#cache?.stamp === stamp) return { ...this.#cache.result, rules: [...this.#cache.result.rules] };
    const result = this.#read();
    this.#cache = { stamp, result };
    return { ...result, rules: [...result.rules] };
  }

  #read(): { rules: LocalRule[]; problem?: string } {
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch (error) {
      return (error as NodeJS.ErrnoException)?.code === "ENOENT"
        ? { rules: [] }
        : { rules: [], problem: "rules.json could not be read" };
    }
    let parsed: { rules?: unknown };
    try {
      parsed = JSON.parse(raw) as { rules?: unknown };
    } catch {
      return { rules: [], problem: "rules.json is not valid JSON" };
    }
    if (!Array.isArray(parsed.rules)) return { rules: [], problem: "rules.json has no rules list" };
    const home = homedir();
    const rules: LocalRule[] = [];
    for (const item of parsed.rules) {
      const entry = (item ?? {}) as Record<string, unknown>;
      const rule = typeof entry.rule === "string" ? entry.rule.trim() : "";
      if (typeof entry.id !== "string" || validateRule(rule)) continue;
      // Earlier drafts stored a path in `scope`; read it as a project rule.
      let scope: RuleScope = "user";
      let project: string | undefined;
      if (entry.scope === "project" && typeof entry.project === "string") {
        scope = "project";
        project = entry.project;
      } else if (typeof entry.scope === "string" && !["user", "~", "~/"].includes(entry.scope.trim()) && entry.scope.trim()) {
        scope = "project";
        project = expandHome(entry.scope.trim(), home);
      }
      if (scope === "project" && (!project || !isAbsolute(project))) continue;
      rules.push({
        id: entry.id,
        rule,
        scope,
        ...(project ? { project } : {}),
        enabled: entry.enabled !== false,
        addedAt: typeof entry.addedAt === "string" ? entry.addedAt : "",
        ...(typeof entry.session === "string" ? { session: entry.session } : {}),
      });
    }
    return { rules };
  }

  save(rules: readonly LocalRule[]): void {
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.${process.pid}.tmp`;
    writeFileSync(tmp, `${JSON.stringify({ version: 2, rules }, null, 2)}\n`, { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, this.path);
    this.#cache = undefined;
  }
}
