// The human authorization ledger: what the human actually typed this session,
// with the assistant text each message answered. It exists because the
// reviewer's transcript evidence anchors on the latest user-role message, which
// in agent-to-agent work is usually a channel notification, and because after
// compaction the original authorization survives only in an agent-written
// summary that must not count as authorization.
//
// Trust: entries come only from pi `input` events whose source is
// "interactive". Channel/muster deliveries and this extension's own retry
// messages arrive as "extension" input and are never recorded. The ledger lives
// in extension memory only, so an agent cannot forge an entry by editing a
// file; it survives compaction and is cleared on session_start, so a restart or
// resume starts empty (fail safe). Keystrokes injected into the pane (tmux
// send-keys) would look interactive, which is why the reviewer treats keystroke
// injection as control tampering.

/** A human permission decision; absent for a typed message. */
export type LedgerDecisionKind =
  | "approved"
  | "approved_for_session"
  | "denied"
  | "approved_retry"
  | "break_glass";

export type LedgerEntry = {
  at: string;
  text: string;
  /** Tail of the assistant text the human was answering; agent-authored. */
  inReplyTo?: string;
  kind?: LedgerDecisionKind;
};

export type InputLike = { text: string; source: string };

const MAX_TEXT_CHARACTERS = 1_500;
const MAX_REPLY_CHARACTERS = 2_500;
const MAX_DECISION_CHARACTERS = 600;
// The line muster types into a pane to nudge an agent; not the human.
const MUSTER_NUDGE_PREFIX = "📬 check your muster inbox";

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

export class AuthorizationLedger {
  readonly #entries: Array<LedgerEntry & { atMs: number }> = [];
  // Decisions are kept separately so a run of dialog clicks can never push
  // the human's typed messages (the planning-session authorization) out.
  readonly #decisions: Array<LedgerEntry & { atMs: number }> = [];
  private readonly now: () => number;
  private readonly maxEntries: number;
  private readonly maxDecisions: number;
  private readonly maxAgeMs: number;

  constructor(options: { now?: () => number; maxEntries?: number; maxDecisions?: number; maxAgeMs?: number } = {}) {
    this.now = options.now ?? Date.now;
    this.maxEntries = options.maxEntries ?? 8;
    this.maxDecisions = options.maxDecisions ?? 8;
    this.maxAgeMs = options.maxAgeMs ?? 24 * 60 * 60 * 1_000;
  }

  /** Record a permission decision the human made (dialog click, approve, break-glass). */
  recordDecision(entry: { kind: LedgerDecisionKind; text: string }): void {
    const atMs = this.now();
    this.#decisions.push({
      atMs,
      at: new Date(atMs).toISOString(),
      kind: entry.kind,
      text: entry.text.trim().slice(0, MAX_DECISION_CHARACTERS),
    });
    while (this.#decisions.length > this.maxDecisions) this.#decisions.shift();
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
  }

  entries(): LedgerEntry[] {
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
}
