// Standing authorization rules the human adds from inside pi with
// /auto-review-rules. They live next to the kempt-managed user config, in
// <pi agent dir>/extensions/pi-auto-review/rules.json, so a `kempt update`
// never overwrites them. That directory is a protected write target (see
// review/guards.ts), and the panel saves only after a confirmation typed in
// the TUI, so an agent cannot add a rule for itself.
import { chmodSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { userConfigPath } from "./config.ts";
import type { StandingAuthorization } from "./types.ts";

export type LocalRule = StandingAuthorization & {
  id: string;
  /** ISO time the human added (or last edited) the rule. */
  addedAt: string;
  /** Session the rule was added from, for the panel's history line. */
  session?: string;
};

export const MAX_RULE_CHARACTERS = 1_000;

export function rulesPath(): string {
  return join(dirname(userConfigPath()), "rules.json");
}

export function validateRule(rule: string, scope: string): string | undefined {
  if (!rule.trim()) return "the rule is empty";
  if (rule.length > MAX_RULE_CHARACTERS) return `the rule is longer than ${MAX_RULE_CHARACTERS} characters`;
  if (/[\u0000-\u001f]/.test(rule) || /[\u0000-\u001f]/.test(scope)) return "the rule or scope contains a control character";
  return undefined;
}

export class RulesStore {
  readonly path: string;

  constructor(options: { path?: string } = {}) {
    this.path = options.path ?? rulesPath();
  }

  /** Never throws: a missing or unreadable file means no local rules (fail safe). */
  load(): { rules: LocalRule[]; problem?: string } {
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch (error) {
      return (error as NodeJS.ErrnoException)?.code === "ENOENT"
        ? { rules: [] }
        : { rules: [], problem: "rules.json could not be read" };
    }
    try {
      const parsed = JSON.parse(raw) as { rules?: unknown };
      if (!Array.isArray(parsed.rules)) return { rules: [], problem: "rules.json has no rules list" };
      const rules: LocalRule[] = [];
      for (const item of parsed.rules) {
        const entry = item as Record<string, unknown>;
        const rule = typeof entry?.rule === "string" ? entry.rule.trim() : "";
        const scope = typeof entry?.scope === "string" ? entry.scope.trim() : "";
        if (typeof entry?.id !== "string" || validateRule(rule, scope)) continue;
        rules.push({
          id: entry.id,
          rule,
          ...(scope ? { scope } : {}),
          addedAt: typeof entry.addedAt === "string" ? entry.addedAt : "",
          ...(typeof entry.session === "string" ? { session: entry.session } : {}),
        });
      }
      return { rules };
    } catch {
      return { rules: [], problem: "rules.json is not valid JSON" };
    }
  }

  save(rules: readonly LocalRule[]): void {
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.${process.pid}.tmp`;
    writeFileSync(tmp, `${JSON.stringify({ version: 1, rules }, null, 2)}\n`, { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, this.path);
  }
}
