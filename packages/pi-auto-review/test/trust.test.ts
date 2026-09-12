import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  applyProjectConfig,
  applyUserConfig,
  assertTrustedInstallation,
  loadConfig,
  loadTrustedConfig,
  userConfigPath,
} from "../src/index.ts";

const TEST_TMP_ROOT = join(
  dirname(fileURLToPath(import.meta.url)),
  ".tmp",
);

function makeTempDir(prefix: string): string {
  mkdirSync(TEST_TMP_ROOT, { recursive: true });
  return mkdtempSync(join(TEST_TMP_ROOT, prefix));
}

test("project config can only tighten trusted settings and is frozen", () => {
  const trusted = loadConfig();
  const effective = applyProjectConfig(trusted, {
    timeoutMs: 10_000,
    retries: 0,
    maxReviewerInputTokens: 4_096,
    breakGlassEnabled: false,
    failureMode: "deny",
    autoConfirmBoundedAllows: [],
  });
  assert.equal(effective.timeoutMs, 10_000);
  assert.equal(effective.retries, 0);
  assert.equal(effective.maxReviewerInputTokens, 4_096);
  assert.equal(effective.breakGlassEnabled, false);
  assert.deepEqual(effective.policyAudit, { enabled: true, retentionDays: 180 });
  assert.equal(effective.model, trusted.model);
  assert.deepEqual(effective.autoConfirmBoundedAllows, []);
  assert.equal(Object.isFrozen(effective), true);
  assert.equal(Object.isFrozen(effective.autoConfirmBoundedAllows), true);

  assert.throws(() =>
    applyProjectConfig(trusted, { model: "attacker/reviewer" }),
  );
  assert.throws(() =>
    applyProjectConfig(trusted, { reviewer: "attacker" }),
  );
  assert.throws(() =>
    applyProjectConfig(trusted, {
      reviewers: {
        attacker: { model: "attacker/reviewer", reasoning: "off" },
      },
    }),
  );
  assert.deepEqual(applyProjectConfig(trusted, { policyAudit: { retentionDays: 30 } }).policyAudit, {
    enabled: true,
    retentionDays: 30,
  });
  assert.deepEqual(applyProjectConfig(trusted, { policyAudit: { enabled: false } }).policyAudit, {
    enabled: false,
    retentionDays: 180,
  });
  assert.throws(() => applyProjectConfig(trusted, { policyAudit: { retentionDays: 181 } }));
  assert.throws(() => applyProjectConfig({ ...trusted, policyAudit: { enabled: false, retentionDays: 180 } }, { policyAudit: { enabled: true } }));
  assert.throws(() =>
    applyProjectConfig(trusted, { grantTtlMs: trusted.grantTtlMs + 1 }),
  );
  assert.throws(() =>
    applyProjectConfig(trusted, {
      maxReviewerInputTokens: trusted.maxReviewerInputTokens + 1,
    }),
  );
  assert.throws(() =>
    applyProjectConfig(trusted, { failureMode: "defer" }),
  );
  assert.throws(() =>
    applyProjectConfig(
      { ...trusted, breakGlassEnabled: false },
      { breakGlassEnabled: true },
    ),
  );
  assert.throws(() =>
    applyProjectConfig(
      { ...trusted, autoConfirmBoundedAllows: [] },
      { autoConfirmBoundedAllows: ["external_directory"] },
    ),
  );
});

test("user config can fully overlay package trusted settings", () => {
  const packageConfig = loadConfig();
  assert.equal(packageConfig.model, "codex-auto-review");
  assert.equal(packageConfig.maxTokens, 256);
  assert.equal(packageConfig.maxReviewerInputTokens, 8_192);
  assert.equal(packageConfig.breakGlassEnabled, true);
  const effective = applyUserConfig(packageConfig, {
    model: "user-provider/other-reviewer",
    autoConfirmBoundedAllows: ["external_directory", "path"],
    timeoutMs: 12_000,
    failureMode: "defer",
    policyAudit: { retentionDays: 365 },
  });
  assert.equal(effective.model, "user-provider/other-reviewer");
  assert.deepEqual(effective.autoConfirmBoundedAllows, [
    "external_directory",
    "path",
  ]);
  assert.equal(effective.timeoutMs, 12_000);
  assert.equal(effective.failureMode, "defer");
  assert.deepEqual(effective.policyAudit, { enabled: true, retentionDays: 365 });
  assert.equal(effective.retries, packageConfig.retries);

  const profiled = applyUserConfig(packageConfig, {
    reviewer: "terra",
    reviewers: {
      sonnet: {
        model: "claude-bridge/claude-sonnet-4-6",
        reasoning: "off",
      },
      terra: {
        model: "openai-codex/gpt-5.6-terra",
        reasoning: "off",
      },
    },
  });
  assert.equal(profiled.reviewer, "terra");
  assert.equal(profiled.model, "openai-codex/gpt-5.6-terra");
  assert.equal(profiled.reasoning, "off");
  assert.deepEqual(Object.keys(profiled.reviewers ?? {}), ["sonnet", "terra"]);
  assert.equal(Object.isFrozen(profiled.reviewers), true);
  assert.equal(Object.isFrozen(profiled.reviewers?.terra), true);

  assert.throws(() =>
    applyUserConfig(packageConfig, {
      reviewer: "missing",
      reviewers: {
        terra: { model: "openai-codex/gpt-5.6-terra", reasoning: "off" },
      },
    }),
  );
  assert.throws(() =>
    applyUserConfig(packageConfig, {
      reviewers: {
        terra: { model: "openai-codex/gpt-5.6-terra", reasoning: "invalid" },
      },
    }),
  );
  assert.throws(() =>
    applyUserConfig(packageConfig, {
      reviewers: {
        "bad name": { model: "openai-codex/gpt-5.6-terra", reasoning: "off" },
      },
    }),
  );
  const prototypeNamed = applyUserConfig(
    packageConfig,
    JSON.parse(JSON.stringify({
      reviewer: "toString",
      reviewers: {
        toString: {
          model: "openai-codex/gpt-5.6-terra",
          reasoning: "off",
        },
      },
    })),
  );
  assert.equal(prototypeNamed.model, "openai-codex/gpt-5.6-terra");
  assert.deepEqual(Object.keys(prototypeNamed.reviewers ?? {}), ["toString"]);
  assert.equal(Object.getPrototypeOf(prototypeNamed.reviewers), null);

  const bareModel = applyUserConfig(packageConfig, {
    model: "codex-auto-review",
  });
  assert.equal(bareModel.model, "codex-auto-review");

  assert.throws(() => applyUserConfig(packageConfig, { model: "" }));
  assert.throws(() => applyUserConfig(packageConfig, { policyAudit: null }));
  for (const surface of [
    "path_read",
    "path_write",
    "external_directory_read",
    "external_directory_write",
  ]) {
    assert.throws(() =>
      applyUserConfig(packageConfig, { autoConfirmBoundedAllows: [surface] }),
    );
  }
  assert.throws(() =>
    applyUserConfig(packageConfig, { maxReviewerInputTokens: 2_047 }),
  );
  assert.throws(() =>
    applyUserConfig(packageConfig, { maxReviewerInputTokens: 32_769 }),
  );
  // Multi-segment model ids (provider/group/model) are valid and resolve like
  // parseModelRef: first segment is the provider, the rest is the model id.
  const nestedModel = applyUserConfig(packageConfig, {
    model: "acme/exam-group/example-flash",
  });
  assert.equal(nestedModel.model, "acme/exam-group/example-flash");
  // Malformed ids with empty segments are rejected.
  assert.throws(() =>
    applyUserConfig(packageConfig, { model: "provider/" }),
  );
  assert.throws(() =>
    applyUserConfig(packageConfig, { model: "/provider/model" }),
  );
  assert.throws(() =>
    applyUserConfig(packageConfig, { model: "a//b" }),
  );
  assert.throws(() =>
    applyUserConfig(packageConfig, { model: "has space" }),
  );
});

test("loadTrustedConfig merges optional user file over package defaults", () => {
  const root = makeTempDir("pi-auto-review-user-config-");
  const userPath = join(root, "config.json");
  const packageConfig = loadConfig();
  try {
    assert.deepEqual(
      loadTrustedConfig({
        packageConfig,
        userConfigPath: join(root, "missing.json"),
      }),
      packageConfig,
    );

    writeFileSync(
      userPath,
      JSON.stringify({
        autoConfirmBoundedAllows: ["external_directory", "path"],
      }),
    );
    const trusted = loadTrustedConfig({
      packageConfig,
      userConfigPath: userPath,
    });
    assert.deepEqual(trusted.autoConfirmBoundedAllows, [
      "external_directory",
      "path",
    ]);
    assert.equal(trusted.model, packageConfig.model);

    const project = applyProjectConfig(trusted, {
      autoConfirmBoundedAllows: ["external_directory"],
    });
    assert.deepEqual(project.autoConfirmBoundedAllows, ["external_directory"]);
    assert.throws(() =>
      applyProjectConfig(
        { ...packageConfig, autoConfirmBoundedAllows: ["external_directory"] },
        {
          autoConfirmBoundedAllows: ["external_directory", "path"],
        },
      ),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("userConfigPath resolves under the agent extensions directory", () => {
  assert.equal(
    userConfigPath("/home/demo"),
    "/home/demo/.pi/agent/extensions/pi-auto-review/config.json",
  );
});

test("security package loaded from the workspace is rejected", () => {
  const root = makeTempDir("pi-auto-review-trust-");
  const packageRoot = join(root, "packages", "pi-auto-review");
  mkdirSync(packageRoot, { recursive: true });
  try {
    assert.throws(
      () => assertTrustedInstallation(root, packageRoot),
      /agent-writable workspace/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
