import assert from "node:assert/strict";
import test from "node:test";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
  JEV_QUESTIONS,
  buildJevState,
  parseAnswers,
  policyOutcome,
  reviewWithJev,
} from "../src/review/jev-reviewer.ts";
import { loadConfig, type Config } from "../src/index.ts";
import { ReviewExecutionError } from "../src/review/types.ts";
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

// --- Task 3: reviewWithJev executor -------------------------------------

// Real SessionManager (inMemory) seeded with user messages, so reviewWithJev
// exercises the production buildContextEntries() path (mirrors the harness in
// authorizer-integration.test.ts).
function makeFakeCtx(userMessages: string[]): ExtensionContext {
  const sessionManager = SessionManager.inMemory(process.cwd(), {
    id: "jev-test-session",
  });
  for (const content of userMessages) {
    sessionManager.appendMessage(
      { role: "user", content } as Parameters<
        typeof sessionManager.appendMessage
      >[0],
    );
  }
  return { cwd: process.cwd(), sessionManager } as unknown as ExtensionContext;
}

function baseConfig(overrides: Partial<Config> = {}): Config {
  return { ...loadConfig(), retries: 0, timeoutMs: 1_000, ...overrides };
}

const jevRequest = {
  id: "jr1",
  source: "permission-system",
  surface: "bash",
  operation: "bash",
  cwd: "/w",
  command: "cat README.md",
} as unknown as BoundaryRequest;

test("reviewWithJev returns an allow ReviewResult from a Jev allow verdict", async () => {
  const ctx = makeFakeCtx(["please read the file"]);
  const client = {
    evaluate: async () => ({
      answers: {
        outcome: { type: "choice", choice: "allow", confidence: 0.95 },
        risk_level: { type: "score", score: 0 },
        hazard_credential_exfiltration: { type: "noul", noul: 0.02 },
        hazard_destructive_wipe: { type: "noul", noul: 0.01 },
        hazard_control_tampering: { type: "noul", noul: 0.02 },
      },
      latencyMs: 120,
    }),
  };
  const result = await reviewWithJev(
    ctx,
    baseConfig(),
    jevRequest,
    undefined,
    { model: "jev-latest" },
    { client },
  );
  assert.equal(result.decision.outcome, "allow");
  assert.equal(result.decision.user_authorization, "unknown");
  assert.equal(result.attempts, 1);
  assert.deepEqual(result.retryErrors, []);
  assert.equal(result.summary.transcript, result.transcript);
});

test("reviewWithJev passes the model and timeout through to the client", async () => {
  const ctx = makeFakeCtx(["do the thing"]);
  const seen: { state?: unknown; questions?: unknown; opts?: unknown } = {};
  const client = {
    evaluate: async (state: unknown, questions: unknown, opts: unknown) => {
      seen.state = state;
      seen.questions = questions;
      seen.opts = opts;
      return {
        answers: {
          outcome: { type: "choice", choice: "defer", confidence: 0.6 },
          risk_level: { type: "score", score: 2 },
        },
        latencyMs: 5,
      };
    },
  };
  const result = await reviewWithJev(
    ctx,
    baseConfig(),
    jevRequest,
    undefined,
    { model: "jev-x", timeoutMs: 4_321 },
    { client },
  );
  assert.equal(result.decision.outcome, "defer");
  assert.deepEqual(seen.opts, { model: "jev-x", timeoutMs: 4_321 });
  assert.equal(seen.questions, JEV_QUESTIONS);
  assert.equal(
    (seen.state as Record<string, unknown>).userAuthorizationCeiling !==
      undefined,
    true,
  );
});

test("reviewWithJev fails closed on client error (throws ReviewExecutionError)", async () => {
  const ctx = makeFakeCtx(["do a thing"]);
  const client = {
    evaluate: async () => {
      throw new Error("typesafe down");
    },
  };
  await assert.rejects(
    reviewWithJev(
      ctx,
      baseConfig(),
      jevRequest,
      undefined,
      { model: "jev-latest" },
      { client },
    ),
    (error: unknown) =>
      error instanceof ReviewExecutionError &&
      error.errorClass === "jev_error",
  );
});
