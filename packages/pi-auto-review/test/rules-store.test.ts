import assert from "node:assert/strict";
import test from "node:test";
import { mkdirSync, mkdtempSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { localRulesFor, projectRootFor, RulesStore, validateRule, type LocalRule } from "../src/review/rules-store.ts";

const store = () => new RulesStore({ path: join(mkdtempSync(join(tmpdir(), "rules-")), "pi-auto-review", "rules.json") });
const rule = (over: Partial<LocalRule>): LocalRule => ({ id: "r", rule: "x", scope: "user", enabled: true, addedAt: "", ...over });

function repoWithWorktree() {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "proj-")));
  const main = join(base, "app");
  mkdirSync(join(main, ".git", "worktrees", "feat"), { recursive: true });
  mkdirSync(join(main, "packages", "core"), { recursive: true });
  const wt = join(base, "app-feat");
  mkdirSync(join(wt, "src"), { recursive: true });
  writeFileSync(join(wt, ".git"), `gitdir: ${join(main, ".git", "worktrees", "feat")}\n`);
  writeFileSync(join(main, ".git", "worktrees", "feat", "gitdir"), `${join(wt, ".git")}\n`);
  const other = join(base, "other");
  mkdirSync(join(other, ".git"), { recursive: true });
  return { main, wt, other, outside: base };
}

test("a missing rules file means no rules; saved rules round-trip with 0600", () => {
  const s = store();
  assert.deepEqual(s.load(), { rules: [] });
  s.save([rule({ id: "r1", rule: "Promoting releases is routine.", scope: "project", project: "/Users/x/app" })]);
  assert.equal(statSync(s.path).mode & 0o777, 0o600);
  assert.deepEqual(s.load().rules.map((r) => [r.rule, r.scope, r.project, r.enabled]), [["Promoting releases is routine.", "project", "/Users/x/app", true]]);
});

test("a corrupt rules file fails safe; bad entries are skipped; old path scopes load as project rules", () => {
  const s = store();
  s.save([]);
  writeFileSync(s.path, "{not json");
  assert.deepEqual(s.load().rules, []);
  assert.match(s.load().problem ?? "", /not valid JSON/);
  writeFileSync(s.path, JSON.stringify({ rules: [
    { id: "a", rule: "" },
    { id: "b", rule: "ok" },
    { rule: "no id" },
    { id: "c", rule: "old draft", scope: "~/GitHub/app" },
    { id: "d", rule: "bad project", scope: "project", project: "relative/path" },
    { id: "e", rule: "off", enabled: false },
    { id: "f", rule: "home draft", scope: "~" },
  ] }));
  const rules = s.load().rules;
  assert.deepEqual(rules.map((r) => r.id), ["b", "c", "e", "f"]);
  assert.equal(rules[3]!.scope, "user", "a ~ scope becomes a User rule, not a project of all of ~");
  assert.deepEqual([rules[1]!.scope, rules[1]!.project], ["project", join(homedir(), "GitHub/app")]);
  assert.equal(rules[2]!.enabled, false);
});

test("validateRule refuses empty, oversized and control-character rules", () => {
  assert.equal(validateRule("fine"), undefined);
  assert.match(validateRule("  ") ?? "", /empty/);
  assert.match(validateRule("x".repeat(1_001)) ?? "", /longer/);
  assert.match(validateRule("a\u001b[31m") ?? "", /control/);
});

test("projectRootFor maps a linked worktree to its main checkout", () => {
  const { main, wt, other, outside } = repoWithWorktree();
  assert.equal(projectRootFor(join(main, "packages", "core")), main);
  assert.equal(projectRootFor(join(wt, "src")), main);
  assert.equal(projectRootFor(other), other);
  assert.equal(projectRootFor(outside), undefined);
  // A planted .git file pointing at another repo's worktree metadata, with no
  // link back, is its own root, not the other project.
  const planted = join(outside, "planted");
  mkdirSync(planted, { recursive: true });
  writeFileSync(join(planted, ".git"), `gitdir: ${join(main, ".git", "worktrees", "feat")}\n`);
  assert.equal(projectRootFor(planted), planted);
});

test("user rules apply everywhere; project rules to the repo and its worktrees; disabled rules nowhere", () => {
  const { main, wt, other } = repoWithWorktree();
  const rules = [
    rule({ id: "u", rule: "user rule" }),
    rule({ id: "p", rule: "project rule", scope: "project", project: main }),
    rule({ id: "off", rule: "disabled", enabled: false }),
  ];
  assert.deepEqual(localRulesFor(rules, join(main, "packages")), ["user rule", "project rule"]);
  assert.deepEqual(localRulesFor(rules, join(wt, "src")), ["user rule", "project rule"]);
  assert.deepEqual(localRulesFor(rules, other), ["user rule"]);
});

test("load reparses only when the file changes", () => {
  const s = store();
  s.save([rule({ id: "a", rule: "one" })]);
  assert.deepEqual(s.load().rules.map((r) => r.rule), ["one"]);
  s.save([rule({ id: "a", rule: "one" }), rule({ id: "b", rule: "two" })]);
  assert.deepEqual(s.load().rules.map((r) => r.rule), ["one", "two"]);
});

test("rules.json is a protected write target (an agent cannot add its own rule)", async () => {
  const { protectedWriteHardDeny } = await import("../src/review/guards.ts");
  const { rulesPath } = await import("../src/review/rules-store.ts");
  const denied = protectedWriteHardDeny({ id: "w", source: "permission-system", surface: "path_write", operation: "write", cwd: "/tmp", path: rulesPath() } as never);
  assert.equal(denied?.rule, "security-control-tampering");
});
