import assert from "node:assert/strict";
import test from "node:test";
import {
  AuthorizationLedger,
  lastAssistantText,
  shouldRecordInput,
} from "../src/review/authorization-ledger.ts";

test("only human-typed conversational input is recorded", () => {
  assert.equal(shouldRecordInput({ text: "yes, go ahead with the plan", source: "interactive" }), true);
  // Channel/muster deliveries, host retry messages and RPC never count.
  assert.equal(shouldRecordInput({ text: "muster: reply from x on thread #1", source: "extension" }), false);
  assert.equal(shouldRecordInput({ text: "go ahead", source: "rpc" }), false);
  // Commands, shell escapes and the muster tmux nudge are not authorizations.
  assert.equal(shouldRecordInput({ text: "/auto-review-model", source: "interactive" }), false);
  assert.equal(shouldRecordInput({ text: "!ls", source: "interactive" }), false);
  assert.equal(shouldRecordInput({ text: "📬 check your muster inbox: call get_inbox", source: "interactive" }), false);
  assert.equal(shouldRecordInput({ text: "   ", source: "interactive" }), false);
});

test("ledger keeps the recent human messages with what they answered", () => {
  let now = 1_000_000;
  const ledger = new AuthorizationLedger({ now: () => now, maxEntries: 3, maxAgeMs: 10_000 });
  ledger.record({ text: "a".repeat(5_000), inReplyTo: "p".repeat(3_000) + "PLAN-END" });
  const [first] = ledger.entries();
  assert.equal(first!.text.length, 1_500);
  // The tail of the proposal is kept: that's where the plan's ask usually is.
  assert.equal(first!.inReplyTo!.length, 2_500);
  assert.ok(first!.inReplyTo!.endsWith("PLAN-END"));
  assert.equal(first!.at, new Date(1_000_000).toISOString());
  for (const t of ["b", "c", "d"]) { now += 1; ledger.record({ text: t }); }
  assert.deepEqual(ledger.entries().map((e) => e.text), ["b", "c", "d"]);
  now += 20_000; // older than maxAgeMs
  assert.deepEqual(ledger.entries(), []);
  ledger.record({ text: "e" });
  ledger.clear();
  assert.deepEqual(ledger.entries(), []);
});

test("lastAssistantText finds the latest assistant prose", () => {
  const entries = [
    { message: { role: "assistant", content: [{ type: "text", text: "old plan" }] } },
    { message: { role: "user", content: "question" } },
    { message: { role: "assistant", content: [{ type: "toolCall", id: "x" }, { type: "text", text: "new plan: merge #444" }] } },
    { message: { role: "toolResult", content: [{ type: "text", text: "ok" }] } },
  ];
  assert.equal(lastAssistantText(entries), "new plan: merge #444");
  assert.equal(lastAssistantText([]), undefined);
});

test("a repeated message (compaction replay) is recorded once", () => {
  const ledger = new AuthorizationLedger();
  ledger.record({ text: "yes, deploy it", inReplyTo: "Plan: deploy" });
  ledger.record({ text: "yes, deploy it", inReplyTo: "Plan: deploy" });
  ledger.record({ text: "and then publish" });
  assert.deepEqual(ledger.entries().map((e) => e.text), ["yes, deploy it", "and then publish"]);
});
