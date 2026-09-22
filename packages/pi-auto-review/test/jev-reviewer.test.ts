import assert from "node:assert/strict";
import test from "node:test";
import { JEV_QUESTIONS, buildJevState, parseAnswers, policyOutcome } from "../src/review/jev-reviewer.ts";
import type { BoundaryRequest } from "../src/broker/types.ts";

const request = { id: "r1", source: "permission-system", surface: "bash", operation: "bash", cwd: "/w", command: "rm -rf /tmp/x" } as unknown as BoundaryRequest;
const transcript = { reviewerEvidence: { userMessages: [{ content: "clean temp" }], toolCalls: [], relevantResults: [] }, userAuthorizationCeiling: "low", truncated: false } as any;

test("JEV_QUESTIONS carries the choice/score/noul set", () => {
  assert.equal((JEV_QUESTIONS as any).outcome.type, "choice");
  assert.equal((JEV_QUESTIONS as any).risk_level.type, "score");
  assert.equal((JEV_QUESTIONS as any).hazard_credential_exfiltration.type, "noul");
});

test("buildJevState mirrors request identity + evidence + ceiling", () => {
  const s = buildJevState(request, transcript) as any;
  assert.equal(s.request.command, "rm -rf /tmp/x");
  assert.equal(s.userAuthorizationCeiling, "low");
  assert.deepEqual(s.evidence.userMessages, ["clean temp"]);
});

test("parseAnswers maps SDK answer shape", () => {
  const v = parseAnswers({ outcome: { type: "choice", choice: "deny", confidence: 0.9 }, risk_level: { type: "score", score: 3 }, hazard_credential_exfiltration: { type: "noul", noul: 0.9 } });
  assert.equal(v.outcome, "deny"); assert.equal(v.risk, 3); assert.equal(v.haz?.credential, 0.9);
});

test("policyOutcome thresholds", () => {
  assert.equal(policyOutcome({ haz: { credential: 0.7 } }), "deny");
  assert.equal(policyOutcome({ risk: 3 }), "deny");
  assert.equal(policyOutcome({ outcome: "deny" }), "deny");
  assert.equal(policyOutcome({ risk: 2 }), "defer");
  assert.equal(policyOutcome({ outcome: "defer" }), "defer");
  assert.equal(policyOutcome({ outcome: "allow", risk: 0, choiceConfidence: 0.4 }), "defer");
  assert.equal(policyOutcome({ outcome: "allow", risk: 0, choiceConfidence: 0.9 }), "allow");
});

import { jevVerdictToDecision } from "../src/review/jev-reviewer.ts";

test("jevVerdictToDecision maps outcome, risk band, unknown auth, rationale", () => {
  const d = jevVerdictToDecision({ outcome: "deny", risk: 3, choiceConfidence: 0.95, haz: { credential: 0.9, wipe: 0.01, control: 0.02 } });
  assert.equal(d.outcome, "deny");
  assert.equal(d.risk_level, "critical");
  assert.equal(d.user_authorization, "unknown");
  assert.ok(d.rationale.length > 0 && d.rationale.length <= 600);
  // risk banding
  assert.equal(jevVerdictToDecision({ risk: 0, outcome: "allow", choiceConfidence: 0.9 }).risk_level, "low");
  assert.equal(jevVerdictToDecision({ risk: 1, outcome: "allow", choiceConfidence: 0.9 }).risk_level, "medium");
  assert.equal(jevVerdictToDecision({ risk: 2, outcome: "allow" }).risk_level, "high");
});
