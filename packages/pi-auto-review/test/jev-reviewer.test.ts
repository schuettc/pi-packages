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

// Fail-open regression guard: a degenerate Jev response (empty or missing the
// outcome choice) must NEVER map to allow. parseAnswers never throws, so the
// safety must live in policyOutcome — a missing/unrecognized outcome defers.
test("reviewWithJev with empty answers ({}) does not allow (defers)", async () => {
  const ctx = makeFakeCtx(["please read the file"]);
  const client = {
    evaluate: async () => ({ answers: {}, latencyMs: 3 }),
  };
  const result = await reviewWithJev(
    ctx,
    baseConfig(),
    jevRequest,
    undefined,
    { model: "jev-latest" },
    { client },
  );
  assert.notEqual(result.decision.outcome, "allow");
  assert.equal(result.decision.outcome, "defer");
});

test("reviewWithJev with a missing outcome.choice does not allow (defers)", async () => {
  const ctx = makeFakeCtx(["please read the file"]);
  const client = {
    evaluate: async () => ({
      answers: {
        // outcome present but without a recognized choice
        outcome: { type: "choice", confidence: 0.99 },
        risk_level: { type: "score", score: 0 },
        hazard_credential_exfiltration: { type: "noul", noul: 0.01 },
      },
      latencyMs: 4,
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
  assert.notEqual(result.decision.outcome, "allow");
  assert.equal(result.decision.outcome, "defer");
});

// Direct policyOutcome guards for the closed fail-open: no valid allow choice
// (undefined outcome) defers even when risk is low and confidence high.
test("policyOutcome defers when there is no valid allow choice", () => {
  assert.equal(policyOutcome({}), "defer");
  assert.equal(policyOutcome({ risk: 0, choiceConfidence: 0.99 }), "defer");
});

// --- Task 7: Jev reviewer diagnostics ------------------------------------

import * as diagnosticsChannel from "node:diagnostics_channel";
import {
  sanitizeErrorMessage,
  classifyJevError,
  snapshotHttpEnv,
  traceJevNetwork,
} from "../src/review/jev-reviewer.ts";
import { completeTelemetry } from "../src/review/provider.ts";

const allowAnswers = {
  outcome: { type: "choice", choice: "allow", confidence: 0.95 },
  risk_level: { type: "score", score: 0 },
  hazard_credential_exfiltration: { type: "noul", noul: 0.02 },
  hazard_destructive_wipe: { type: "noul", noul: 0.01 },
  hazard_control_tampering: { type: "noul", noul: 0.02 },
};

async function captureJevFailure(
  evaluate: () => Promise<never>,
): Promise<ReviewExecutionError> {
  const ctx = makeFakeCtx(["do a thing"]);
  let caught: unknown;
  await assert.rejects(
    reviewWithJev(ctx, baseConfig(), jevRequest, undefined, { model: "jev-latest" }, {
      client: { evaluate },
    }).catch((error: unknown) => {
      caught = error;
      throw error;
    }),
  );
  assert.ok(caught instanceof ReviewExecutionError);
  return caught;
}

test("sanitizeErrorMessage redacts bearer tokens and ts_ keys, one line, <=300 chars", () => {
  const out = sanitizeErrorMessage(new Error("boom\nBearer ts_abcdefghijk123 and ts_secretsecret99 " + "x".repeat(400)));
  assert.ok(!out.includes("ts_abcdefghijk123") && !out.includes("ts_secretsecret99"));
  assert.ok(out.includes("<redacted"));
  assert.ok(!out.includes("\n"));
  assert.ok(out.length <= 300);
});

test("classifyJevError maps SDK error names/statuses to review error classes", () => {
  const err = (name: string, status?: number) => Object.assign(new Error(name), { name, ...(status ? { status } : {}) });
  assert.equal(classifyJevError(err("APITimeoutError")), "timeout");
  assert.equal(classifyJevError(err("APIConnectionError")), "transient_connection");
  assert.equal(classifyJevError(err("AuthenticationError", 401)), "authentication");
  assert.equal(classifyJevError(err("TypeSafeConfigError")), "authentication");
  assert.equal(classifyJevError(err("RateLimitError", 429)), "rate_limit");
  assert.equal(classifyJevError(err("APIError", 503)), "transient_server");
  assert.equal(classifyJevError(new Error("weird")), "jev_error");
});

test("reviewWithJev success records stage timings + ok diagnostics", async () => {
  const ctx = makeFakeCtx(["please read the file"]);
  const client = {
    evaluate: async () => ({ answers: allowAnswers, latencyMs: 7 }),
    isConfigured: async () => true,
  };
  const result = await reviewWithJev(
    ctx,
    baseConfig(),
    jevRequest,
    undefined,
    { model: "jev-latest" },
    { client, dispatchStartedAt: Date.now() - 5 },
  );
  assert.equal(result.decision.outcome, "allow");
  const diag = result.summary.jevDiagnostics;
  assert.ok(diag);
  assert.equal(diag.outcome, "ok");
  assert.equal(typeof diag.stages.evaluate, "number");
  assert.equal(typeof diag.stages.transcript, "number");
  assert.equal(typeof diag.stages.preflight, "number");
  assert.equal(typeof diag.stages.keyCheck, "number");
  assert.equal(typeof diag.stages.map, "number");
  assert.ok((diag.stages.clientResolve ?? -1) >= 0);
  assert.equal(diag.keyConfigured, true);
  assert.ok(!Number.isNaN(Date.parse(diag.at)));
  assert.equal(diag.errorClass, undefined);
  assert.deepEqual(result.summary.errorCounts, {});
  assert.ok(Array.isArray(diag.net));

  // completeTelemetry carries the diagnostics onto review_complete.
  const event = completeTelemetry(
    jevRequest,
    baseConfig(),
    result.summary,
    result.decision.outcome,
    undefined,
    "jev",
    result.jev,
  );
  assert.equal(event.type, "review_complete");
  assert.deepEqual(
    (event as { jevDiagnostics?: unknown }).jevDiagnostics,
    diag,
  );
});

test("reviewWithJev timeout is classified 'timeout', counted, and still fails closed", async () => {
  const err = await captureJevFailure(async () => {
    throw Object.assign(new Error("Request timed out."), { name: "APITimeoutError" });
  });
  assert.equal(err.errorClass, "timeout");
  assert.equal(err.summary.errorCounts.timeout, 1);
  const diag = err.summary.jevDiagnostics;
  assert.ok(diag);
  assert.equal(diag.outcome, "error");
  assert.equal(diag.errorClass, "timeout");
  assert.equal(diag.errorName, "APITimeoutError");
  assert.equal(diag.errorMessage, "Request timed out.");
  assert.equal(typeof diag.stages.evaluate, "number");
  assert.equal(diag.stages.map, undefined);
  assert.equal(diag.keyConfigured, undefined);
  assert.ok((err as Error).cause instanceof Error);
});

test("reviewWithJev generic failure is classified jev_error with sanitized message", async () => {
  const err = await captureJevFailure(async () => {
    throw new Error("upstream said Bearer ts_leakyleakyleaky1");
  });
  assert.equal(err.errorClass, "jev_error");
  assert.equal(err.summary.errorCounts.jev_error, 1);
  const message = err.summary.jevDiagnostics?.errorMessage ?? "";
  assert.ok(message.length > 0);
  assert.ok(!message.includes("ts_leakyleakyleaky1"));
  assert.ok(message.includes("<redacted"));
});

test("reviewWithJev records an HTTP status from a status-bearing error", async () => {
  const err = await captureJevFailure(async () => {
    throw Object.assign(new Error("Service Unavailable"), { name: "APIError", status: 503 });
  });
  assert.equal(err.errorClass, "transient_server");
  assert.equal(err.summary.jevDiagnostics?.errorStatus, 503);
});

test("traceJevNetwork captures only the target host and stop() unsubscribes", () => {
  const channel = diagnosticsChannel.channel("undici:request:create");
  let clock = 100;
  const trace = traceJevNetwork("api.typesafe.ai", () => clock, 90);
  try {
    channel.publish({ request: { origin: "https://api.typesafe.ai", method: "POST", path: "/v1/systemone", headers: ["authorization", "Bearer ts_secretsecret"] } });
    channel.publish({ request: { origin: "https://example.com", method: "GET", path: "/" } });
  } finally {
    trace.stop();
  }
  assert.deepEqual(trace.events, [
    { t: 10, event: "request:create", detail: "POST /v1/systemone" },
  ]);
  assert.ok(!JSON.stringify(trace.events).includes("ts_secretsecret"));
  clock = 200;
  channel.publish({ request: { origin: "https://api.typesafe.ai", method: "POST", path: "/v1/systemone" } });
  assert.equal(trace.events.length, 1);
});

test("snapshotHttpEnv returns strings/boolean and never throws", () => {
  const env = snapshotHttpEnv();
  assert.equal(typeof env.dispatcher, "string");
  assert.equal(typeof env.fetchName, "string");
  assert.equal(typeof env.fetchNative, "boolean");
});

test("policyOutcome: a low-confidence deny choice defers to a human instead of hard-denying", () => {
  // Live canary: Jev chose deny at 0.17 confidence (near-uniform over 3 options) on a read-only ~/.pi search.
  assert.equal(policyOutcome({ outcome: "deny", risk: 0.44, choiceConfidence: 0.17, haz: { credential: 0.29 } }), "defer");
  assert.equal(policyOutcome({ outcome: "deny", risk: 0, choiceConfidence: 0.49 }), "defer");
  // A confident deny still denies; hazard and critical-risk floors still deny regardless of confidence.
  assert.equal(policyOutcome({ outcome: "deny", risk: 0, choiceConfidence: 0.5 }), "deny");
  assert.equal(policyOutcome({ outcome: "allow", risk: 0, choiceConfidence: 0.99, haz: { credential: 0.6 } }), "deny");
  assert.equal(policyOutcome({ outcome: "allow", risk: 3, choiceConfidence: 0.99 }), "deny");
});
