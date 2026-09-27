import { chmodSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// Human authorizations: what the human actually typed in this conversation,
// with the assistant text each message answered, plus the permission decisions
// they made (dialog clicks, /auto-review-approve, break-glass). It exists
// because the reviewer's transcript evidence anchors on the latest user-role
// message, which in agent-to-agent work is usually a channel notification, and
// because after compaction the original authorization survives only in an
// agent-written summary that must not count as authorization.
//
// Trust: typed entries come only from pi `input` events whose source is
// "interactive". Channel/muster deliveries and this extension's own retry
// messages arrive as "extension" input and are never recorded. Keystrokes
// injected into the pane (tmux send-keys) would look interactive, which is why
// the reviewer treats keystroke injection as control tampering.
//
// Persistence: a reload (/reload, kempt update, pi-auto-reload) re-imports the
// extension, so memory alone would forget everything. Each conversation's
// authorizations are saved to <dir>/<session-id>.json and read back when the
// same session starts again (reload or resume). A new or forked session has a
// new id and starts empty. <dir> sits in pi-auto-review's protected directory:
// file-tool writes there are hard-denied, shell writes hit the tamper floor,
// and the reviewer's control-tampering hazard covers the rest. A file that
// doesn't validate, or belongs to another session, is ignored (fail safe);
// entries still expire after 24 hours.

/** A human permission decision; absent for a typed message. */
export type AuthorizationDecisionKind =
  | "approved"
  | "approved_for_session"
  | "denied"
  | "approved_retry"
  | "break_glass";

export type AuthorizationEntry = {
  at: string;
  text: string;
  /** Tail of the assistant text the human was answering; agent-authored. */
  inReplyTo?: string;
  kind?: AuthorizationDecisionKind;
};

export type InputLike = { text: string; source: string };

const MAX_TEXT_CHARACTERS = 1_500;
const MAX_REPLY_CHARACTERS = 2_500;
const MAX_DECISION_CHARACTERS = 600;
// The line muster types into a pane to nudge an agent; not the human.
const MUSTER_NUDGE_PREFIX = "📬 check your muster inbox";
const FILE_VERSION = 1;
const SAFE_SESSION_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const DECISION_KINDS: readonly AuthorizationDecisionKind[] = [
  "approved",
  "approved_for_session",
  "denied",
  "approved_retry",
  "break_glass",
];

export function shouldRecordInput(event: InputLike): boolean {
  if (event.source !== "interactive") return false;
  const text = event.text.trim();
  if (!text) return false;
  if (text.startsWith("/") || text.startsWith("!")) return false;
  if (text.startsWith(MUSTER_NUDGE_PREFIX)) return false;
  return true;
}

// The latest assistant prose in the session, i.e. what a "yes, go ahead"
// refers to. Tool calls and tool results are skipped.
export function lastAssistantText(entries: readonly unknown[]): string | undefined {
  for (let index = entries.length - 1; index >= 0; index--) {
    const message = (entries[index] as { message?: { role?: string; content?: unknown } })?.message;
    if (message?.role !== "assistant") continue;
    const content = message.content;
    const text = typeof content === "string"
      ? content
      : Array.isArray(content)
        ? content
          .filter((part) => part && typeof part === "object" && (part as { type?: string }).type === "text")
          .map((part) => String((part as { text?: unknown }).text ?? ""))
          .join("\n")
        : "";
    if (text.trim()) return text.trim();
  }
  return undefined;
}

export class Authorizations {
  readonly #entries: Array<AuthorizationEntry & { atMs: number }> = [];
  // Decisions are kept separately so a run of dialog clicks can never push
  // the human's typed messages (the planning-session authorization) out.
  readonly #decisions: Array<AuthorizationEntry & { atMs: number }> = [];
  private readonly now: () => number;
  private readonly maxEntries: number;
  private readonly maxDecisions: number;
  private readonly maxAgeMs: number;
  private readonly dir: string | undefined;
  #file: string | undefined;
  #sessionId: string | undefined;

  constructor(options: { now?: () => number; maxEntries?: number; maxDecisions?: number; maxAgeMs?: number; dir?: string } = {}) {
    this.dir = options.dir;
    this.now = options.now ?? Date.now;
    this.maxEntries = options.maxEntries ?? 8;
    this.maxDecisions = options.maxDecisions ?? 8;
    this.maxAgeMs = options.maxAgeMs ?? 24 * 60 * 60 * 1_000;
  }

  /** Record a permission decision the human made (dialog click, approve, break-glass). */
  recordDecision(entry: { kind: AuthorizationDecisionKind; text: string }): void {
    const atMs = this.now();
    this.#decisions.push({
      atMs,
      at: new Date(atMs).toISOString(),
      kind: entry.kind,
      text: entry.text.trim().slice(0, MAX_DECISION_CHARACTERS),
    });
    while (this.#decisions.length > this.maxDecisions) this.#decisions.shift();
    this.#save();
  }

  record(entry: { text: string; inReplyTo?: string }): void {
    const atMs = this.now();
    // pi re-sends queued messages after compaction as interactive input; a
    // repeat of the latest entry must not push real authorizations out.
    const latest = this.#entries.at(-1);
    if (latest && latest.text === entry.text.trim().slice(0, MAX_TEXT_CHARACTERS)) return;
    this.#entries.push({
      atMs,
      at: new Date(atMs).toISOString(),
      text: entry.text.trim().slice(0, MAX_TEXT_CHARACTERS),
      ...(entry.inReplyTo
        ? { inReplyTo: entry.inReplyTo.slice(-MAX_REPLY_CHARACTERS) }
        : {}),
    });
    while (this.#entries.length > this.maxEntries) this.#entries.shift();
    this.#save();
  }

  entries(): AuthorizationEntry[] {
    const cutoff = this.now() - this.maxAgeMs;
    return [...this.#entries, ...this.#decisions]
      .filter((entry) => entry.atMs >= cutoff)
      .sort((a, b) => a.atMs - b.atMs)
      .map(({ atMs: _atMs, ...entry }) => ({ ...entry }));
  }

  clear(): void {
    this.#entries.length = 0;
    this.#decisions.length = 0;
  }

  /**
   * Switch to a conversation: forget what's in memory, then read back that
   * session's saved authorizations (a reload or resume of the same session).
   * Never throws; anything unreadable means an empty start.
   */
  open(sessionId: string): void {
    this.clear();
    this.#sessionId = sessionId;
    this.#file = this.dir && SAFE_SESSION_ID.test(sessionId)
      ? join(this.dir, `${sessionId}.json`)
      : undefined;
    if (!this.#file) return;
    this.#prune();
    try {
      const saved = parseSaved(readFileSync(this.#file, "utf8"), sessionId);
      if (!saved) return;
      const cutoff = this.now() - this.maxAgeMs;
      const keep = (entry: { atMs: number }) => entry.atMs >= cutoff;
      this.#entries.push(...saved.entries.filter(keep).slice(-this.maxEntries).map((entry) => ({
        atMs: entry.atMs,
        at: new Date(entry.atMs).toISOString(),
        text: entry.text.slice(0, MAX_TEXT_CHARACTERS),
        ...(entry.inReplyTo ? { inReplyTo: entry.inReplyTo.slice(-MAX_REPLY_CHARACTERS) } : {}),
      })));
      this.#decisions.push(...saved.decisions.filter(keep).slice(-this.maxDecisions).map((entry) => ({
        atMs: entry.atMs,
        at: new Date(entry.atMs).toISOString(),
        kind: entry.kind,
        text: entry.text.slice(0, MAX_DECISION_CHARACTERS),
      })));
    } catch {
      // Missing (a new session) or unreadable: start empty.
    }
  }

  #save(): void {
    if (!this.#file || !this.dir) return;
    try {
      mkdirSync(this.dir, { recursive: true, mode: 0o700 });
      chmodSync(this.dir, 0o700);
      const body = {
        version: FILE_VERSION,
        sessionId: this.#sessionId,
        entries: this.#entries.map(({ atMs, text, inReplyTo }) => ({ atMs, text, ...(inReplyTo ? { inReplyTo } : {}) })),
        decisions: this.#decisions.map(({ atMs, kind, text }) => ({ atMs, kind, text })),
      };
      const tmp = `${this.#file}.${process.pid}.tmp`;
      writeFileSync(tmp, `${JSON.stringify(body)}\n`, { mode: 0o600 });
      chmodSync(tmp, 0o600);
      renameSync(tmp, this.#file);
    } catch {
      // Saving is best effort; the in-memory copy still serves this session.
    }
  }

  // Drop files for conversations untouched longer than the expiry.
  #prune(): void {
    if (!this.dir) return;
    try {
      const cutoff = this.now() - this.maxAgeMs;
      for (const name of readdirSync(this.dir)) {
        if (!name.endsWith(".json")) continue;
        const path = join(this.dir, name);
        try {
          if (path !== this.#file && lstatSync(path).mtimeMs < cutoff) rmSync(path, { force: true });
        } catch {
          // One unreadable entry doesn't stop the rest.
        }
      }
    } catch {
      // Pruning is housekeeping; never let it block a session.
    }
  }
}

type SavedEntry = { atMs: number; text: string; inReplyTo?: string };
type SavedDecision = { atMs: number; kind: AuthorizationDecisionKind; text: string };

// Strict: any entry that doesn't validate rejects the whole file.
function parseSaved(raw: string, sessionId: string): { entries: SavedEntry[]; decisions: SavedDecision[] } | undefined {
  const data = JSON.parse(raw) as Record<string, unknown>;
  if (!data || data.version !== FILE_VERSION || data.sessionId !== sessionId) return undefined;
  if (!Array.isArray(data.entries) || !Array.isArray(data.decisions)) return undefined;
  const time = (v: unknown) => typeof v === "number" && Number.isFinite(v);
  const text = (v: unknown) => typeof v === "string" && v.trim().length > 0;
  const entries: SavedEntry[] = [];
  for (const item of data.entries) {
    const e = (item ?? {}) as Record<string, unknown>;
    if (!time(e.atMs) || !text(e.text)) return undefined;
    if (e.inReplyTo !== undefined && typeof e.inReplyTo !== "string") return undefined;
    entries.push({ atMs: e.atMs as number, text: e.text as string, ...(e.inReplyTo ? { inReplyTo: e.inReplyTo as string } : {}) });
  }
  const decisions: SavedDecision[] = [];
  for (const item of data.decisions) {
    const d = (item ?? {}) as Record<string, unknown>;
    if (!time(d.atMs) || !text(d.text) || !DECISION_KINDS.includes(d.kind as AuthorizationDecisionKind)) return undefined;
    decisions.push({ atMs: d.atMs as number, kind: d.kind as AuthorizationDecisionKind, text: d.text as string });
  }
  return { entries, decisions };
}
