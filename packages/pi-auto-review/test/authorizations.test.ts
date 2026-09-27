import assert from "node:assert/strict";
import test from "node:test";
import {
  Authorizations,
  lastAssistantText,
  shouldRecordInput,
} from "../src/review/authorizations.ts";

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

test("authorizations keep the recent human messages with what they answered", () => {
  let now = 1_000_000;
  const authz = new Authorizations({ now: () => now, maxEntries: 3, maxAgeMs: 10_000 });
  authz.record({ text: "a".repeat(5_000), inReplyTo: "p".repeat(3_000) + "PLAN-END" });
  const [first] = authz.entries();
  assert.equal(first!.text.length, 1_500);
  // The tail of the proposal is kept: that's where the plan's ask usually is.
  assert.equal(first!.inReplyTo!.length, 2_500);
  assert.ok(first!.inReplyTo!.endsWith("PLAN-END"));
  assert.equal(first!.at, new Date(1_000_000).toISOString());
  for (const t of ["b", "c", "d"]) { now += 1; authz.record({ text: t }); }
  assert.deepEqual(authz.entries().map((e) => e.text), ["b", "c", "d"]);
  now += 20_000; // older than maxAgeMs
  assert.deepEqual(authz.entries(), []);
  authz.record({ text: "e" });
  authz.clear();
  assert.deepEqual(authz.entries(), []);
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
  const authz = new Authorizations();
  authz.record({ text: "yes, deploy it", inReplyTo: "Plan: deploy" });
  authz.record({ text: "yes, deploy it", inReplyTo: "Plan: deploy" });
  authz.record({ text: "and then publish" });
  assert.deepEqual(authz.entries().map((e) => e.text), ["yes, deploy it", "and then publish"]);
});

test("human permission decisions are recorded alongside messages, with their own cap", () => {
  let now = 1_000_000;
  const authz = new Authorizations({ now: () => now, maxEntries: 2, maxDecisions: 2 });
  authz.record({ text: "plan the merge" });
  now += 1;
  authz.recordDecision({ kind: "approved", text: "bash: gh pr merge 444 -R org/repo --merge" });
  now += 1;
  authz.record({ text: "and then publish" });
  now += 1;
  authz.recordDecision({ kind: "denied", text: "bash: " + "x".repeat(2_000) });
  const entries = authz.entries();
  // Merged in time order; decisions never push human messages out.
  assert.deepEqual(entries.map((e) => e.kind ?? "message"), ["message", "approved", "message", "denied"]);
  assert.equal(entries[3]!.text.length, 600);
  assert.equal("inReplyTo" in entries[1]!, false);
  now += 1;
  authz.recordDecision({ kind: "approved_for_session", text: "webfetch: docs" });
  now += 1;
  authz.recordDecision({ kind: "break_glass", text: "bash: sed -i ..." });
  assert.deepEqual(authz.entries().filter((e) => e.kind).map((e) => e.kind), ["approved_for_session", "break_glass"]);
  assert.equal(authz.entries().filter((e) => !e.kind).length, 2);
});

import { mkdirSync, mkdtempSync, readdirSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const tempDir = () => join(mkdtempSync(join(tmpdir(), "authz-")), "authorizations");

test("authorizations survive a reload: a new instance for the same session reads them back", () => {
  const dir = tempDir();
  let now = 1_000_000;
  const a = new Authorizations({ dir, now: () => now });
  a.open("sess-1");
  a.record({ text: "yes, go ahead with the plan", inReplyTo: "Plan: merge #444" });
  now += 1;
  a.recordDecision({ kind: "approved", text: "bash: gh pr merge 444 -R org/repo" });
  // A reload re-imports the extension: a brand-new instance, same session id.
  const b = new Authorizations({ dir, now: () => now });
  b.open("sess-1");
  assert.deepEqual(b.entries(), a.entries());
  assert.equal(b.entries().length, 2);
  // The file is private to the user.
  assert.equal(statSync(join(dir, "sess-1.json")).mode & 0o777, 0o600);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
});

test("a different session (new or fork) starts empty; switching sessions resets memory", () => {
  const dir = tempDir();
  const a = new Authorizations({ dir });
  a.open("sess-1");
  a.record({ text: "deploy it" });
  a.open("sess-2");
  assert.deepEqual(a.entries(), []);
  a.open("sess-1");
  assert.deepEqual(a.entries().map((e) => e.text), ["deploy it"]);
});

test("a file that doesn't validate is ignored (fail safe)", () => {
  const dir = tempDir();
  mkdirSync(dir, { recursive: true });
  const cases: unknown[] = [
    "{not json",
    { version: 1, sessionId: "other", entries: [{ atMs: Date.now(), text: "x" }], decisions: [] },
    { version: 1, sessionId: "sess-1", entries: "x", decisions: [] },
    { version: 1, sessionId: "sess-1", entries: [], decisions: [{ atMs: Date.now(), kind: "sudo", text: "x" }] },
    { version: 1, sessionId: "sess-1", entries: [{ atMs: "yesterday", text: "x" }], decisions: [] },
    { version: 1, sessionId: "sess-1", entries: [{ atMs: Date.now(), text: "" }], decisions: [] },
  ];
  for (const c of cases) {
    writeFileSync(join(dir, "sess-1.json"), typeof c === "string" ? c : JSON.stringify(c));
    const a = new Authorizations({ dir });
    a.open("sess-1");
    assert.deepEqual(a.entries(), [], JSON.stringify(c));
  }
});

test("loaded entries keep the caps and the 24h expiry; stale files are pruned", () => {
  const dir = tempDir();
  mkdirSync(dir, { recursive: true });
  let now = 10_000_000;
  writeFileSync(join(dir, "sess-1.json"), JSON.stringify({
    version: 1, sessionId: "sess-1",
    entries: [{ atMs: now - 20_000, text: "old" }, { atMs: now - 1_000, text: "x".repeat(5_000) }],
    decisions: [],
  }));
  writeFileSync(join(dir, "stale.json"), "{}");
  utimesSync(join(dir, "stale.json"), new Date(now - 60_000), new Date(now - 60_000));
  const a = new Authorizations({ dir, now: () => now, maxAgeMs: 10_000 });
  a.open("sess-1");
  const entries = a.entries();
  assert.deepEqual(entries.map((e) => e.text.length), [1_500], "the expired entry is dropped, the long one capped");
  assert.equal(readdirSync(dir).includes("stale.json"), false);
});

test("an unsafe session id, or no directory, keeps authorizations in memory only", () => {
  const dir = tempDir();
  const a = new Authorizations({ dir });
  a.open("../escape");
  a.record({ text: "hi" });
  assert.equal(a.entries().length, 1);
  assert.throws(() => statSync(dir));
  const b = new Authorizations();
  b.open("sess-1");
  b.record({ text: "hi" });
  assert.equal(b.entries().length, 1);
});

test("the saved authorizations are protected from agent writes (file tools and shell)", async () => {
  const { protectedWriteHardDeny, reviewerTamperingHardDeny } = await import("../src/review/guards.ts");
  const { userConfigPath } = await import("../src/review/config.ts");
  const { dirname } = await import("node:path");
  const file = join(dirname(userConfigPath()), "authorizations", "conv-1.json");
  assert.equal(protectedWriteHardDeny({ id: "w", source: "permission-system", surface: "path_write", operation: "write", cwd: "/tmp", path: file } as never)?.rule, "security-control-tampering");
  for (const cmd of [
    `echo '{"version":1}' > ~/.pi/agent/extensions/pi-auto-review/authorizations/conv-1.json`,
    `cp /tmp/forged.json ~/.pi/agent/extensions/pi-auto-review/authorizations/conv-1.json`,
    `python3 -c "open('${file}','w').write('{}')"`,
  ]) assert.equal(reviewerTamperingHardDeny(cmd)?.rule, "security-control-tampering", cmd);
  assert.equal(reviewerTamperingHardDeny(`cat ~/.pi/agent/extensions/pi-auto-review/authorizations/conv-1.json`), undefined);
});
