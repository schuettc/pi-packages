import assert from "node:assert/strict";
import test from "node:test";
import { visibleWidth } from "@earendil-works/pi-tui";
import { RulesPanel, RULES_BOX_WIDTH } from "../src/review/rules-panel.ts";
import type { LocalRule } from "../src/review/rules-store.ts";

const ENTER = "\r";
const ESC = "\x1b";
const DOWN = "\x1b[B";
const TAB = "\t";
const theme = { fg: (_c: string, t: string) => t, bold: (t: string) => t };

function open(opts: { local?: LocalRule[]; suggestion?: { rule: string; scope: string } } = {}) {
  let saved: LocalRule[] = [...(opts.local ?? [])];
  let saves = 0;
  let closed = false;
  const panel = new RulesPanel({
    kemptRules: [{ scope: "~/GitHub/x", rule: "Kempt-managed rule." }],
    store: { load: () => ({ rules: saved }), save: (rules) => { saved = [...rules]; saves++; } },
    defaultScope: "~/GitHub/bettor-help-workspace",
    session: "sess-1",
    now: () => new Date("2026-09-24T19:00:00.000Z"),
    ...(opts.suggestion ? { suggestion: opts.suggestion } : {}),
    theme,
    requestRender: () => {},
    onClose: () => { closed = true; },
  });
  const screen = () => panel.render(120).join("\n").replace(/\x1b\[[0-9;]*m|\x1b_[^\x07]*\x07/g, "");
  const press = (...keys: string[]) => { for (const k of keys) panel.handleInput(k); };
  return { panel, screen, press, saved: () => saved, saves: () => saves, closed: () => closed };
}

test("lists kempt rules read-only, local rules, and an add row, in a bordered box", () => {
  const p = open({ local: [{ id: "r1", rule: "Local rule.", scope: "~/GitHub/y", addedAt: "2026-09-24T18:00:00.000Z" }] });
  const lines = p.panel.render(120);
  for (const l of lines) assert.equal(visibleWidth(l), RULES_BOX_WIDTH);
  assert.ok(lines[0]!.startsWith("╭") && lines.at(-1)!.startsWith("╰"));
  const s = p.screen();
  assert.match(s, /Kempt-managed rule\./);
  assert.match(s, /\(kempt\)/);
  assert.match(s, /Local rule\./);
  assert.match(s, /\+ Add rule/);
});

test("adding a rule needs typing it and confirming with y", () => {
  const p = open();
  p.press(DOWN, ENTER); // the add row
  assert.match(p.screen(), /scope/i);
  p.press(TAB, ..."Restarting help.bettor.* launchd jobs is routine.", ENTER);
  assert.match(p.screen(), /Save this rule\? y\/N/);
  assert.equal(p.saves(), 0, "nothing saved before the confirmation");
  p.press("y");
  assert.equal(p.saves(), 1);
  assert.deepEqual(p.saved().map((r) => [r.scope, r.rule, r.session, r.addedAt]), [
    ["~/GitHub/bettor-help-workspace", "Restarting help.bettor.* launchd jobs is routine.", "sess-1", "2026-09-24T19:00:00.000Z"],
  ]);
});

test("declining the confirmation saves nothing; an empty rule is refused", () => {
  const p = open();
  p.press(DOWN, ENTER, TAB, ..."x", ENTER, "n");
  assert.equal(p.saves(), 0);
  assert.match(p.screen(), /\+ Add rule/, "back on the list");
  p.press(ENTER, TAB, ENTER); // the add row is still selected
  assert.match(p.screen(), /✗ .*empty/);
  assert.equal(p.saves(), 0);
});

test("a local rule can be removed; a kempt rule cannot", () => {
  const p = open({ local: [{ id: "r1", rule: "Local rule.", addedAt: "" }] });
  p.press("d"); // kempt rule selected
  assert.match(p.screen(), /managed in kempt/i);
  p.press(DOWN, "d");
  assert.match(p.screen(), /Remove this rule\? y\/N/);
  p.press("y");
  assert.deepEqual(p.saved(), []);
});

test("a suggestion from a recent approval prefills the add form", () => {
  const p = open({ suggestion: { rule: "gh pr merge 84 -R org/cli --merge is routine.", scope: "~/GitHub/bettor-help-workspace/bettor-help-cli" } });
  assert.match(p.screen(), /\+ Add suggested rule/);
  p.press(ENTER); // suggestion row is selected first
  assert.match(p.screen(), /gh pr merge 84/);
  assert.match(p.screen(), /bettor-help-cli/);
});

test("the box keeps one height across modes; esc closes from the list", () => {
  const p = open({ local: [{ id: "r1", rule: "Local rule.", addedAt: "" }] });
  const heights = new Set<number>();
  heights.add(p.panel.render(120).length);
  p.press(DOWN, "d"); heights.add(p.panel.render(120).length);
  p.press("n", DOWN, ENTER); heights.add(p.panel.render(120).length);
  p.press(ESC); heights.add(p.panel.render(120).length);
  assert.equal(heights.size, 1, [...heights].join(","));
  p.press(ESC);
  assert.equal(p.closed(), true);
});
