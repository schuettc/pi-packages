import assert from "node:assert/strict";
import test from "node:test";
import { visibleWidth } from "@earendil-works/pi-tui";
import { RulesPanel, RULES_BOX_WIDTH, type RecentApproval } from "../src/review/rules-panel.ts";
import type { LocalRule } from "../src/review/rules-store.ts";

const ENTER = "\r";
const ESC = "\x1b";
const DOWN = "\x1b[B";
const UP = "\x1b[A";
const LEFT = "\x1b[D";
const RIGHT = "\x1b[C";
const TAB = "\t";
const theme = { fg: (_c: string, t: string) => t, bold: (t: string) => t };
const PROJECT = "/Users/x/GitHub/bettor-help-cli";
const rule = (over: Partial<LocalRule>): LocalRule => ({ id: "r", rule: "x", scope: "user", enabled: true, addedAt: "", ...over });

function open(opts: { local?: LocalRule[]; recent?: RecentApproval[]; project?: string | null; inactiveReviewer?: string } = {}) {
  let saved: LocalRule[] = [...(opts.local ?? [])];
  let saves = 0;
  let closed = false;
  const project = opts.project === null ? undefined : (opts.project ?? PROJECT);
  const panel = new RulesPanel({
    kemptRules: [{ rule: "Kempt-managed rule." }],
    store: { load: () => ({ rules: saved }), save: (rules) => { saved = [...rules]; saves++; } },
    ...(project ? { project } : {}),
    ...(opts.recent ? { recent: opts.recent } : {}),
    ...(opts.inactiveReviewer ? { inactiveReviewer: opts.inactiveReviewer } : {}),
    session: "sess-1",
    now: () => new Date("2026-09-24T19:00:00.000Z"),
    theme,
    requestRender: () => {},
    onClose: () => { closed = true; },
  });
  const screen = () => panel.render(120).join("\n").replace(/\x1b\[[0-9;]*m|\x1b_[^\x07]*\x07/g, "");
  const press = (...keys: string[]) => { for (const k of keys) panel.handleInput(k); };
  return { panel, screen, press, saved: () => saved, saves: () => saves, closed: () => closed };
}

test("three tabs in a fixed-width bordered box; opens on Project inside a repo", () => {
  const p = open({ local: [rule({ id: "p", rule: "Project rule.", scope: "project", project: PROJECT })] });
  for (const l of p.panel.render(120)) assert.equal(visibleWidth(l), RULES_BOX_WIDTH);
  assert.match(p.screen(), /User 1.*\[Project 1\].*Recent 0/);
  assert.match(p.screen(), /Project rule\./);
  p.press(LEFT);
  assert.match(p.screen(), /\[User 1\]/);
  assert.match(p.screen(), /Kempt-managed rule\. \(kempt\)/);
  assert.match(p.screen(), /\+ Add rule/);
  assert.equal(open({ project: null }).screen().includes("[User"), true, "opens on User outside a repo");
});

test("adding a project rule: scope toggle, rule text, then y to save", () => {
  const p = open();
  p.press(ENTER); // + Add rule on the Project tab
  assert.match(p.screen(), /\(•\) Project: bettor-help-cli and its worktrees/);
  p.press(..."Merging promote/* PRs is routine.", ENTER);
  assert.match(p.screen(), /Save this rule\? y\/N/);
  assert.equal(p.saves(), 0, "nothing saved before y");
  p.press("y");
  assert.deepEqual(p.saved().map((r) => [r.scope, r.project, r.rule, r.enabled, r.session]), [
    ["project", PROJECT, "Merging promote/* PRs is routine.", true, "sess-1"],
  ]);
  // Switch the scope to User in the form.
  p.press(DOWN, ENTER, TAB, RIGHT, TAB, ..."Running tests is routine.", ENTER, "y");
  assert.equal(p.saved().length, 2);
  assert.equal(p.saved()[1]!.scope, "user");
  assert.equal("project" in p.saved()[1]!, false);
});

test("outside a repo only User rules can be added", () => {
  const p = open({ project: null });
  p.press(RIGHT, ENTER);
  assert.match(p.screen(), /Not in a git repository/);
  p.press(LEFT, UP, ENTER, TAB, RIGHT);
  assert.match(p.screen(), /only User is available/);
});

test("space turns a rule off and back on, each after y; declining changes nothing", () => {
  const p = open({ local: [rule({ id: "p", rule: "Project rule.", scope: "project", project: PROJECT })] });
  p.press(" ");
  assert.match(p.screen(), /Disable this rule\? y\/N/);
  p.press("n");
  assert.equal(p.saves(), 0);
  p.press(" ", "y");
  assert.equal(p.saved()[0]!.enabled, false);
  assert.match(p.screen(), /Project rule\. \(off\)/);
  p.press(" ");
  assert.match(p.screen(), /Enable this rule\? y\/N/);
  p.press("y");
  assert.equal(p.saved()[0]!.enabled, true);
});

test("remove asks first; kempt rules can't be changed here", () => {
  const p = open({ local: [rule({ id: "u", rule: "User rule." })] });
  p.press(LEFT, "d");
  assert.match(p.screen(), /managed in kempt/);
  p.press(DOWN, "d");
  assert.match(p.screen(), /Remove this rule\? y\/N/);
  p.press("y");
  assert.deepEqual(p.saved(), []);
});

test("Recent turns an approved action into a draft rule, scoped to its project", () => {
  const p = open({ recent: [{ text: "bash_escalated: gh pr merge 84 -R org/cli --merge", project: PROJECT, at: "2026-09-24T18:20:00.000Z" }] });
  assert.match(p.screen(), /\[Recent 1\]/, "opens on Recent when there are approvals");
  assert.match(p.screen(), /You approved/);
  p.press(ENTER);
  assert.match(p.screen(), /\(•\) Project: bettor-help-cli/);
  assert.match(p.screen(), /gh pr merge 84 -R org\/cli --merge/);
  assert.equal(p.saves(), 0);
});

test("another project's rules are listed and labelled, and keep their project when edited", () => {
  const p = open({ local: [rule({ id: "o", rule: "Other rule.", scope: "project", project: "/Users/x/GitHub/mlb-dk" })] });
  assert.match(p.screen(), /Other rule\. \(mlb-dk\)/);
  p.press(ENTER, " ", "!", ENTER, "y");
  assert.equal(p.saved()[0]!.project, "/Users/x/GitHub/mlb-dk");
});

test("warns when the active reviewer doesn't read rules; fixed height; esc closes", () => {
  assert.match(open({ inactiveReviewer: "sonnet" }).screen(), /Only the Jev reviewer uses these rules; current reviewer: sonnet/);
  const p = open({ local: [rule({ id: "u", rule: "User rule." })], recent: [{ text: "x", at: "2026-09-24T18:00:00.000Z" }] });
  const heights = new Set<number>();
  const snap = () => heights.add(p.panel.render(120).length);
  snap(); p.press(RIGHT); snap(); p.press(RIGHT); snap(); p.press(LEFT, LEFT, DOWN, " "); snap(); p.press("n", ENTER); snap(); p.press(ESC); snap();
  assert.equal(heights.size, 1, [...heights].join(","));
  p.press(ESC);
  assert.equal(p.closed(), true);
});
