import { Input, matchesKey, truncateToWidth, visibleWidth, wrapTextWithAnsi, type Component } from "@earendil-works/pi-tui";
import { randomUUID } from "node:crypto";
import type { StandingAuthorization } from "./types.ts";
import { validateRule, type LocalRule, type RulesStore } from "./rules-store.ts";

// The /auto-review-rules panel: the same bordered look as /typesafe (creel's
// popup), wider so rules are readable. Kempt-managed rules are shown
// read-only; rules added here are saved to rules.json only after the human
// confirms with y. The box keeps one height so the centered overlay never
// jumps.

export const RULES_BOX_WIDTH = 78;
const PADDING = 2;
const INNER = RULES_BOX_WIDTH - 2 - PADDING * 2;
const LIST_ROWS = 8;
const DETAIL_LINES = 4;

export interface RulesPanelTheme {
  fg(color: "accent" | "border" | "dim" | "muted" | "success" | "error" | "warning" | "text", text: string): string;
  bold(text: string): string;
}

export interface RulesPanelOptions {
  kemptRules: readonly Readonly<StandingAuthorization>[];
  store: Pick<RulesStore, "load" | "save">;
  /** Scope prefilled for a new rule (the current project, ~-abbreviated). */
  defaultScope: string;
  /** A draft from the human's most recent approval of a deferred action. */
  suggestion?: { rule: string; scope: string };
  session?: string;
  now?: () => Date;
  theme: RulesPanelTheme;
  requestRender: () => void;
  onClose: () => void;
}

type Row =
  | { kind: "suggest" }
  | { kind: "kempt"; rule: Readonly<StandingAuthorization> }
  | { kind: "local"; rule: LocalRule }
  | { kind: "add" };

export class RulesPanel implements Component {
  #opts: RulesPanelOptions;
  #local: LocalRule[];
  #problem: string | undefined;
  #selected = 0;
  #mode: "list" | "edit" | "confirmSave" | "confirmRemove" = "list";
  #editing: string | undefined;
  #field: "scope" | "rule" = "scope";
  #scope = new Input();
  #rule = new Input();
  #message: { kind: "ok" | "error"; text: string } | undefined;

  constructor(opts: RulesPanelOptions) {
    this.#opts = opts;
    const loaded = opts.store.load();
    this.#local = loaded.rules;
    this.#problem = loaded.problem;
  }

  invalidate(): void {}

  #rows(): Row[] {
    return [
      ...(this.#opts.suggestion ? [{ kind: "suggest" } as const] : []),
      ...this.#opts.kemptRules.map((rule) => ({ kind: "kempt", rule }) as const),
      ...this.#local.map((rule) => ({ kind: "local", rule }) as const),
      { kind: "add" } as const,
    ];
  }

  render(width: number): string[] {
    const { theme } = this.#opts;
    const body: string[] = [];
    if (this.#mode === "list" || this.#mode === "confirmRemove") {
      const rows = this.#rows();
      const top = Math.max(0, Math.min(this.#selected - LIST_ROWS + 1, rows.length - LIST_ROWS));
      rows.slice(top, top + LIST_ROWS).forEach((row, offset) => {
        const active = top + offset === this.#selected;
        const pointer = active ? theme.fg("accent", "→ ") : "  ";
        body.push(pointer + this.#rowLabel(row, active));
      });
      while (body.length < LIST_ROWS) body.push("");
      body.push("");
      const detail = this.#mode === "confirmRemove"
        ? [theme.fg("warning", "Remove this rule? y/N")]
        : this.#detail(rows[this.#selected]!);
      body.push(...detail.slice(0, DETAIL_LINES));
      while (body.length < LIST_ROWS + 1 + DETAIL_LINES) body.push("");
    } else {
      this.#scope.focused = this.#mode === "edit" && this.#field === "scope";
      this.#rule.focused = this.#mode === "edit" && this.#field === "rule";
      body.push(theme.fg("dim", "Scope: commands run inside this directory (empty = anywhere)"));
      body.push(...this.#field_(this.#scope, this.#scope.focused));
      body.push("");
      body.push(theme.fg("dim", "Rule: what's routine, specific enough for a command to show it"));
      body.push(...this.#field_(this.#rule, this.#rule.focused));
      body.push("");
      if (this.#mode === "confirmSave") {
        for (const line of wrapTextWithAnsi(this.#rule.getValue(), INNER).slice(0, 3)) body.push(theme.fg("text", line));
        body.push(theme.fg("warning", "Save this rule? y/N"));
      }
      while (body.length < LIST_ROWS + 1 + DETAIL_LINES) body.push("");
      body.length = LIST_ROWS + 1 + DETAIL_LINES;
    }
    body.push("");
    body.push(this.#message
      ? this.#message.kind === "ok" ? theme.fg("success", `✓ ${this.#message.text}`) : theme.fg("error", `✗ ${this.#message.text}`)
      : this.#problem ? theme.fg("warning", `! ${this.#problem}`) : "");
    return this.#box(body, width);
  }

  handleInput(data: string): void {
    if (this.#mode === "confirmSave") {
      if (data === "y" || data === "Y") this.#save();
      else { this.#mode = "list"; this.#message = { kind: "ok", text: "Not saved." }; }
      this.#opts.requestRender();
      return;
    }
    if (this.#mode === "confirmRemove") {
      if (data === "y" || data === "Y") this.#remove();
      else this.#message = { kind: "ok", text: "Kept the rule." };
      this.#mode = "list";
      this.#opts.requestRender();
      return;
    }
    if (this.#mode === "edit") {
      if (matchesKey(data, "escape")) { this.#mode = "list"; this.#message = undefined; }
      else if (matchesKey(data, "tab")) this.#field = this.#field === "scope" ? "rule" : "scope";
      else if (matchesKey(data, "enter") || data === "\n") {
        if (this.#field === "scope") this.#field = "rule";
        else {
          const problem = validateRule(this.#rule.getValue(), this.#scope.getValue());
          if (problem) this.#message = { kind: "error", text: `Not saved: ${problem}` };
          else { this.#mode = "confirmSave"; this.#message = undefined; }
        }
      } else (this.#field === "scope" ? this.#scope : this.#rule).handleInput(data);
      this.#opts.requestRender();
      return;
    }
    const rows = this.#rows();
    const row = rows[this.#selected]!;
    if (matchesKey(data, "escape") || matchesKey(data, "ctrl+c")) { this.#opts.onClose(); return; }
    if (matchesKey(data, "up") || data === "k") { this.#selected = (this.#selected + rows.length - 1) % rows.length; this.#message = undefined; }
    else if (matchesKey(data, "down") || data === "j") { this.#selected = (this.#selected + 1) % rows.length; this.#message = undefined; }
    else if (matchesKey(data, "enter") || data === "\n" || data === " ") this.#activate(row);
    else if (data === "d" || data === "x" || matchesKey(data, "delete")) {
      if (row.kind === "local") this.#mode = "confirmRemove";
      else if (row.kind === "kempt") this.#message = { kind: "error", text: "This rule is managed in kempt; change it in your dotfiles." };
    } else return;
    this.#opts.requestRender();
  }

  #activate(row: Row): void {
    this.#message = undefined;
    if (row.kind === "kempt") {
      this.#message = { kind: "error", text: "This rule is managed in kempt; change it in your dotfiles." };
      return;
    }
    const draft = row.kind === "local"
      ? { scope: row.rule.scope ?? "", rule: row.rule.rule, id: row.rule.id }
      : row.kind === "suggest" && this.#opts.suggestion
        ? { ...this.#opts.suggestion, id: undefined }
        : { scope: this.#opts.defaultScope, rule: "", id: undefined };
    this.#editing = draft.id;
    this.#scope.setValue(draft.scope);
    this.#rule.setValue(draft.rule);
    // Put the cursor at the end of prefilled text (ctrl+e).
    this.#scope.handleInput("\x05");
    this.#rule.handleInput("\x05");
    this.#field = row.kind === "add" ? "scope" : "rule";
    this.#mode = "edit";
  }

  #save(): void {
    const rule = this.#rule.getValue().trim();
    const scope = this.#scope.getValue().trim();
    const entry: LocalRule = {
      id: this.#editing ?? randomUUID(),
      rule,
      ...(scope ? { scope } : {}),
      addedAt: (this.#opts.now?.() ?? new Date()).toISOString(),
      ...(this.#opts.session ? { session: this.#opts.session } : {}),
    };
    const next = this.#editing
      ? this.#local.map((r) => (r.id === this.#editing ? entry : r))
      : [...this.#local, entry];
    try {
      this.#opts.store.save(next);
      this.#local = next;
      this.#message = { kind: "ok", text: "Rule saved. It applies to the next review." };
    } catch {
      this.#message = { kind: "error", text: "Could not write rules.json; nothing changed." };
    }
    this.#mode = "list";
  }

  #remove(): void {
    const row = this.#rows()[this.#selected];
    if (row?.kind !== "local") return;
    const next = this.#local.filter((r) => r.id !== row.rule.id);
    try {
      this.#opts.store.save(next);
      this.#local = next;
      this.#selected = Math.min(this.#selected, this.#rows().length - 1);
      this.#message = { kind: "ok", text: "Rule removed." };
    } catch {
      this.#message = { kind: "error", text: "Could not write rules.json; nothing changed." };
    }
  }

  // The focused field renders as pi's Input (with its cursor); the other
  // shows its text plainly.
  #field_(input: Input, focused: boolean): string[] {
    return focused
      ? input.render(INNER)
      : [this.#opts.theme.fg("muted", truncateToWidth(`  ${input.getValue()}`, INNER, "…"))];
  }

  #rowLabel(row: Row, active: boolean): string {
    const { theme } = this.#opts;
    const color = active ? "accent" : "text";
    if (row.kind === "suggest") return theme.fg("warning", "+ Add suggested rule (from your last approval)");
    if (row.kind === "add") return theme.fg(color, "+ Add rule");
    const tag = row.kind === "kempt" ? " (kempt)" : "";
    const text = truncateToWidth(row.rule.rule, INNER - 2 - tag.length, "…");
    return theme.fg(color, text) + theme.fg("dim", tag);
  }

  #detail(row: Row): string[] {
    const { theme } = this.#opts;
    if (row.kind === "add") return [theme.fg("dim", "Add a standing rule: routine work Jev should treat as authorized.")];
    if (row.kind === "suggest") {
      return [theme.fg("dim", `Draft: ${this.#opts.suggestion?.rule ?? ""}`), theme.fg("dim", "Enter to edit it into a general rule, then confirm.")];
    }
    const lines = wrapTextWithAnsi(row.rule.rule, INNER).slice(0, DETAIL_LINES - 1).map((l) => theme.fg("text", l));
    const scope = row.rule.scope ? `in ${row.rule.scope}` : "everywhere";
    const origin = row.kind === "kempt" ? "managed in kempt" : row.rule.addedAt ? `added ${row.rule.addedAt.slice(0, 16).replace("T", " ")}Z` : "added here";
    lines.push(theme.fg("dim", `${scope} · ${origin}`));
    return lines;
  }

  #footer(): string {
    if (this.#mode === "edit") return "tab switch field · enter next/save · esc back";
    if (this.#mode === "confirmSave" || this.#mode === "confirmRemove") return "y confirm · any other key cancels";
    return "↑↓ select · enter edit · d remove · esc close";
  }

  #box(body: string[], width: number): string[] {
    const { theme } = this.#opts;
    const outer = Math.max(20, Math.min(RULES_BOX_WIDTH, width));
    const inner = outer - 2 - PADDING * 2;
    const border = (t: string) => theme.fg("border", t);
    const row = (content: string) => {
      const fitted = truncateToWidth(content, inner, "…");
      return `${border("│")}${" ".repeat(PADDING)}${fitted}${" ".repeat(Math.max(0, inner - visibleWidth(fitted)))}${" ".repeat(PADDING)}${border("│")}`;
    };
    const lines = [theme.bold("🛡 auto-review · standing rules"), "", ...body, "", theme.fg("dim", this.#footer())];
    return [border(`╭${"─".repeat(outer - 2)}╮`), ...lines.map(row), border(`╰${"─".repeat(outer - 2)}╯`)];
  }
}
