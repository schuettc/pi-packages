import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, statSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_CONFIG, standingAuthorizationsFor } from "../src/review/config.ts";
import { RulesStore, validateRule } from "../src/review/rules-store.ts";

const store = () => new RulesStore({ path: join(mkdtempSync(join(tmpdir(), "rules-")), "pi-auto-review", "rules.json") });

test("a missing rules file means no rules; saved rules round-trip with 0600", () => {
  const s = store();
  assert.deepEqual(s.load(), { rules: [] });
  s.save([{ id: "r1", scope: "~/GitHub/bettor-help-workspace", rule: "Promoting releases is routine.", addedAt: "2026-09-24T19:00:00.000Z", session: "sess-1" }]);
  assert.equal(statSync(s.path).mode & 0o777, 0o600);
  assert.deepEqual(s.load().rules.map((r) => r.rule), ["Promoting releases is routine."]);
});

test("a corrupt rules file fails safe to no rules, with a problem to show", () => {
  const s = store();
  s.save([]);
  writeFileSync(s.path, "{not json");
  const loaded = s.load();
  assert.deepEqual(loaded.rules, []);
  assert.match(loaded.problem ?? "", /not valid JSON/);
  // Invalid entries are skipped, valid ones kept.
  writeFileSync(s.path, JSON.stringify({ rules: [{ id: "a", rule: "" }, { id: "b", rule: "ok" }, { rule: "no id" }] }));
  assert.deepEqual(s.load().rules.map((r) => r.id), ["b"]);
});

test("validateRule refuses empty, oversized and control-character rules", () => {
  assert.equal(validateRule("fine", ""), undefined);
  assert.match(validateRule("  ", "") ?? "", /empty/);
  assert.match(validateRule("x".repeat(1_001), "") ?? "", /longer/);
  assert.match(validateRule("a\u001b[31m", "") ?? "", /control/);
  assert.match(validateRule("fine", ".") ?? "", /must start with ~ or \//);
  assert.match(validateRule("fine", "src/app") ?? "", /must start with ~ or \//);
  assert.equal(validateRule("fine", "~/GitHub/x"), undefined);
  assert.equal(validateRule("fine", "/Users/x/proj"), undefined);
});

test("rules from the panel join the kempt rules, scoped by cwd", () => {
  const cfg = { ...DEFAULT_CONFIG, standingAuthorizations: [{ rule: "kempt rule" }] };
  const local = [
    { scope: "~/GitHub/bettor-help-workspace", rule: "local scoped" },
    { scope: "~/GitHub/other", rule: "elsewhere" },
  ];
  assert.deepEqual(
    standingAuthorizationsFor(cfg, join(homedir(), "GitHub/bettor-help-workspace/nfl-dk"), local),
    ["kempt rule", "local scoped"],
  );
});

test("rules.json is a protected write target (an agent cannot add its own rule)", async () => {
  const { protectedWriteHardDeny } = await import("../src/review/guards.ts");
  const { rulesPath } = await import("../src/review/rules-store.ts");
  const denied = protectedWriteHardDeny({ id: "w", source: "permission-system", surface: "path_write", operation: "write", cwd: "/tmp", path: rulesPath() } as never);
  assert.equal(denied?.rule, "security-control-tampering");
});

test("a relative scope never matches (it would resolve against pi's own cwd)", () => {
  assert.deepEqual(standingAuthorizationsFor({ ...DEFAULT_CONFIG }, process.cwd(), [{ scope: ".", rule: "dot" }, { scope: "src", rule: "src" }]), []);
});

test("load reparses only when the file changes", () => {
  const s = store();
  s.save([{ id: "a", rule: "one", addedAt: "" }]);
  assert.deepEqual(s.load().rules.map((r) => r.rule), ["one"]);
  s.save([{ id: "a", rule: "one" , addedAt: "" }, { id: "b", rule: "two", addedAt: "" }]);
  assert.deepEqual(s.load().rules.map((r) => r.rule), ["one", "two"]);
});
