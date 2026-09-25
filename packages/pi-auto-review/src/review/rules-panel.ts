import { Input, matchesKey, truncateToWidth, visibleWidth, wrapTextWithAnsi, type Component } from "@earendil-works/pi-tui";
import { randomUUID } from "node:crypto";
import { basename } from "node:path";
import type { StandingAuthorization } from "./types.ts";
import { validateRule, type LocalRule, type RuleScope, type RulesStore } from "./rules-store.ts";

// The /auto-review-rules panel: the same bordered look as /typesafe (creel's
// popup), wider so rules are readable. Three tabs:
//   User     rules for every project on this machine (kempt rules read-only)
//   Project  rules for one git repository and all its worktrees
//   Recent   deferred actions the human approved, to turn into rules
// Adding a rule, editing one, and enabling one all end in a y/N the human
// types. Disabling or removing also asks. The box keeps one height, so the
// centered overlay never jumps.

export const RULES_BOX_WIDTH = 78;
const PADDING = 2;
const INNER = RULES_BOX_WIDTH - 2 - PADDING * 2;
const LIST_ROWS = 8;
const DETAIL_LINES = 4;
const BODY_LINES = 2 + LIST_ROWS + 1 + DETAIL_LINES;
const TABS = ["user", "project", "recent"] as const;
type Tab = (typeof TABS)[number];

export interface RulesPanelTheme {
  fg(color: "accent" | "border" | "dim" | "muted" | "success" | "error" | "warning" | "text", text: string): string;
  bold(text: string): string;
}

export type RecentApproval = { text: string; project?: string; at: string };

export interface RulesPanelOptions {
  kemptRules: readonly Readonly<StandingAuthorization>[];
  store: Pick<RulesStore, "load" | "save">;
  /** The git repository the session is in (main checkout root), if any. */
  project?: string;
  /** Deferred actions the human approved this session, newest first. */
  recent?: readonly RecentApproval[];
  /** Tab to open on; defaults to Recent when it has entries, else Project or User. */
  initialTab?: Tab;
  /** Set when the active reviewer does not read standing rules (not a Jev profile). */
  inactiveReviewer?: string;
  session?: string;
  now?: () => Date;
  theme: RulesPanelTheme;
  requestRender: () => void;
  onClose: () => void;
}

type Row =
  | { kind: "kempt"; rule: Readonly<StandingAuthorization> }
  | { kind: "local"; rule: LocalRule }
  | { kind: "recent"; item: RecentApproval }
  | { kind: "add" };

type Pending = { kind: "save" | "remove" | "enable" | "disable"; id?: string };

export class RulesPanel implements Component {
  #opts: RulesPanelOptions;
  #local: LocalRule[];
  #problem: string | undefined;
  #tab: Tab;
  #selected: Record<Tab, number> = { user: 0, project: 0, recent: 0 };
  #mode: "list" | "edit" | "confirm" = "list";
  #pending: Pending | undefined;
  #editing: string | undefined;
  #field: "scope" | "rule" = "rule";
  #scope: RuleScope = "user";
  #rule = new Input();
  #message: { kind: "ok" | "error"; text: string } | undefined;

  constructor(opts: RulesPanelOptions) {
    this.#opts = opts;
    const loaded = opts.store.load();
    this.#local = loaded.rules;
    this.#problem = loaded.problem;
    this.#tab = opts.initialTab ?? ((opts.recent?.length ?? 0) > 0 ? "recent" : opts.project ? "project" : "user");
  }

  invalidate(): void {}

  #rows(tab: Tab = this.#tab): Row[] {
    if (tab === "recent") return (this.#opts.recent ?? []).map((item) => ({ kind: "recent", item }) as const);
    if (tab === "user") {
      return [
        ...this.#opts.kemptRules.map((rule) => ({ kind: "kempt", rule }) as const),
        ...this.#local.filter((r) => r.scope === "user").map((rule) => ({ kind: "local", rule }) as const),
        { kind: "add" } as const,
      ];
    }
    // This project's rules first, then other projects', so all stay manageable.
    const here = this.#opts.project;
    const project = this.#local.filter((r) => r.scope === "project");
    const ordered = [...project.filter((r) => r.project === here), ...project.filter((r) => r.project !== here)];
    return [...ordered.map((rule) => ({ kind: "local", rule }) as const), { kind: "add" } as const];
  }

  #row(): Row | undefined {
    return this.#rows()[this.#selected[this.#tab]];
  }

  render(width: number): string[] {
    const { theme } = this.#opts;
    const body: string[] = [this.#tabBar(), ""];
    if (this.#mode === "edit" || (this.#mode === "confirm" && this.#pending?.kind === "save")) {
      body.push(...this.#form());
    } else {
      const rows = this.#rows();
      const selected = this.#selected[this.#tab];
      const top = Math.max(0, Math.min(selected - LIST_ROWS + 1, rows.length - LIST_ROWS));
      if (rows.length === 0) body.push(theme.fg("dim", "No approvals yet this session."));
      rows.slice(top, top + LIST_ROWS).forEach((row, offset) => {
        const active = top + offset === selected;
        body.push((active ? theme.fg("accent", "→ ") : "  ") + this.#rowLabel(row, active));
      });
      while (body.length < 2 + LIST_ROWS) body.push("");
      body.push("");
      const detail = this.#mode === "confirm" ? [theme.fg("warning", this.#confirmText())] : this.#detail(rows[selected]);
      body.push(...detail.slice(0, DETAIL_LINES));
    }
    while (body.length < BODY_LINES) body.push("");
    body.length = BODY_LINES;
    body.push("");
    body.push(this.#message
      ? this.#message.kind === "ok" ? theme.fg("success", `✓ ${this.#message.text}`) : theme.fg("error", `✗ ${this.#message.text}`)
      : this.#problem ? theme.fg("warning", `! ${this.#problem}`)
      : this.#opts.inactiveReviewer
        ? theme.fg("warning", `! Only the Jev reviewer uses these rules; current reviewer: ${this.#opts.inactiveReviewer}`)
        : "");
    return this.#box(body, width);
  }

  handleInput(data: string): void {
    if (this.#mode === "confirm") {
      const yes = data === "y" || data === "Y";
      const pending = this.#pending;
      this.#pending = undefined;
      this.#mode = "list";
      if (yes && pending) this.#apply(pending);
      else this.#message = { kind: "ok", text: "Nothing changed." };
      this.#opts.requestRender();
      return;
    }
    if (this.#mode === "edit") {
      this.#handleEdit(data);
      this.#opts.requestRender();
      return;
    }
    const rows = this.#rows();
    const row = rows[this.#selected[this.#tab]];
    if (matchesKey(data, "escape") || matchesKey(data, "ctrl+c")) { this.#opts.onClose(); return; }
    if (matchesKey(data, "left") || matchesKey(data, "right") || data === "h" || data === "l") {
      const step = matchesKey(data, "left") || data === "h" ? -1 : 1;
      this.#tab = TABS[(TABS.indexOf(this.#tab) + step + TABS.length) % TABS.length]!;
      this.#message = undefined;
    } else if (matchesKey(data, "up") || data === "k") {
      if (rows.length) this.#selected[this.#tab] = (this.#selected[this.#tab] + rows.length - 1) % rows.length;
      this.#message = undefined;
    } else if (matchesKey(data, "down") || data === "j") {
      if (rows.length) this.#selected[this.#tab] = (this.#selected[this.#tab] + 1) % rows.length;
      this.#message = undefined;
    } else if (matchesKey(data, "enter") || data === "\n") {
      if (row) this.#activate(row);
    } else if (data === " ") {
      if (row?.kind === "local") this.#ask({ kind: row.rule.enabled ? "disable" : "enable", id: row.rule.id });
      else if (row?.kind === "kempt") this.#message = { kind: "error", text: "This rule is managed in kempt; change it in your dotfiles." };
    } else if (data === "d" || data === "x" || matchesKey(data, "delete")) {
      if (row?.kind === "local") this.#ask({ kind: "remove", id: row.rule.id });
      else if (row?.kind === "kempt") this.#message = { kind: "error", text: "This rule is managed in kempt; change it in your dotfiles." };
    } else {
      return;
    }
    this.#opts.requestRender();
  }

  #handleEdit(data: string): void {
    if (matchesKey(data, "escape")) { this.#mode = "list"; this.#message = undefined; return; }
    if (matchesKey(data, "tab") || matchesKey(data, "shift+tab")) {
      this.#field = this.#field === "scope" ? "rule" : "scope";
      return;
    }
    if (this.#field === "scope") {
      if (matchesKey(data, "left") || matchesKey(data, "right") || data === " ") this.#toggleScope();
      else if (matchesKey(data, "enter") || data === "\n") this.#field = "rule";
      return;
    }
    if (matchesKey(data, "enter") || data === "\n") {
      const problem = validateRule(this.#rule.getValue());
      if (problem) this.#message = { kind: "error", text: `Not saved: ${problem}` };
      else if (this.#scope === "project" && !this.#opts.project) this.#message = { kind: "error", text: "Not in a git repository: choose User." };
      else { this.#message = undefined; this.#ask({ kind: "save" }); }
      return;
    }
    this.#rule.handleInput(data);
  }

  #toggleScope(): void {
    if (this.#scope === "user" && !this.#opts.project) {
      this.#message = { kind: "error", text: "Not in a git repository, so only User is available." };
      return;
    }
    this.#scope = this.#scope === "user" ? "project" : "user";
  }

  #activate(row: Row): void {
    this.#message = undefined;
    if (row.kind === "kempt") {
      this.#message = { kind: "error", text: "This rule is managed in kempt; change it in your dotfiles." };
      return;
    }
    if (row.kind === "local") {
      this.#open(row.rule.id, row.rule.scope, row.rule.rule);
    } else if (row.kind === "recent") {
      this.#open(undefined, row.item.project && row.item.project === this.#opts.project ? "project" : "user", row.item.text);
    } else if (this.#tab === "project" && !this.#opts.project) {
      this.#message = { kind: "error", text: "Not in a git repository: add a User rule instead." };
    } else {
      this.#open(undefined, this.#tab === "project" ? "project" : "user", "");
    }
  }

  #open(id: string | undefined, scope: RuleScope, text: string): void {
    this.#editing = id;
    this.#scope = scope;
    this.#rule.setValue(text);
    this.#rule.handleInput("\x05"); // cursor to the end (ctrl+e)
    this.#field = "rule";
    this.#mode = "edit";
  }

  #ask(pending: Pending): void {
    this.#pending = pending;
    this.#mode = "confirm";
  }

  #confirmText(): string {
    switch (this.#pending?.kind) {
      case "remove": return "Remove this rule? y/N";
      case "enable": return "Enable this rule? y/N";
      case "disable": return "Disable this rule? y/N";
      default: return "Save this rule? y/N";
    }
  }

  #apply(pending: Pending): void {
    let next: LocalRule[];
    let done: string;
    if (pending.kind === "save") {
      const existing = this.#local.find((r) => r.id === this.#editing);
      const entry: LocalRule = {
        id: this.#editing ?? randomUUID(),
        rule: this.#rule.getValue().trim(),
        scope: this.#scope,
        ...(this.#scope === "project" && this.#opts.project ? { project: this.#opts.project } : {}),
        enabled: existing?.enabled ?? true,
        addedAt: (this.#opts.now?.() ?? new Date()).toISOString(),
        ...(this.#opts.session ? { session: this.#opts.session } : {}),
      };
      // Editing a rule from another project keeps that project.
      if (existing?.scope === "project" && this.#scope === "project" && existing.project) entry.project = existing.project;
      next = existing ? this.#local.map((r) => (r.id === entry.id ? entry : r)) : [...this.#local, entry];
      done = "Rule saved. It applies from the next review.";
      this.#tab = entry.scope;
    } else if (pending.kind === "remove") {
      next = this.#local.filter((r) => r.id !== pending.id);
      done = "Rule removed.";
    } else {
      const enabled = pending.kind === "enable";
      next = this.#local.map((r) => (r.id === pending.id ? { ...r, enabled } : r));
      done = enabled ? "Rule enabled." : "Rule disabled; it stays here, unused.";
    }
    try {
      this.#opts.store.save(next);
      this.#local = next;
      this.#message = { kind: "ok", text: done };
    } catch {
      this.#message = { kind: "error", text: "Could not write rules.json; nothing changed." };
    }
    const count = this.#rows().length;
    this.#selected[this.#tab] = Math.max(0, Math.min(this.#selected[this.#tab], count - 1));
  }

  #projectName(root: string | undefined): string {
    return root ? basename(root) : "no repository";
  }

  #tabBar(): string {
    const { theme } = this.#opts;
    const counts: Record<Tab, number> = {
      user: this.#opts.kemptRules.length + this.#local.filter((r) => r.scope === "user").length,
      project: this.#local.filter((r) => r.scope === "project").length,
      recent: this.#opts.recent?.length ?? 0,
    };
    const labels: Record<Tab, string> = { user: "User", project: "Project", recent: "Recent" };
    return TABS.map((tab) => {
      const text = ` ${labels[tab]} ${counts[tab]} `;
      return tab === this.#tab ? theme.bold(theme.fg("accent", `[${text.trim()}]`)) : theme.fg("dim", ` ${text.trim()} `);
    }).join(theme.fg("dim", "·"));
  }

  #form(): string[] {
    const { theme } = this.#opts;
    const scopeActive = this.#mode === "edit" && this.#field === "scope";
    this.#rule.focused = this.#mode === "edit" && this.#field === "rule";
    const option = (scope: RuleScope, label: string) =>
      this.#scope === scope ? theme.fg("accent", `(•) ${label}`) : theme.fg(scope === "project" && !this.#opts.project ? "dim" : "muted", `( ) ${label}`);
    const lines = [
      theme.fg(scopeActive ? "accent" : "dim", "Applies to"),
      `  ${option("user", "User: every project on this machine")}`,
      `  ${option("project", this.#editingProject() ? `Project: ${this.#projectName(this.#editingProject())} and its worktrees` : "Project: (not in a git repository)")}`,
      "",
      theme.fg(this.#rule.focused ? "accent" : "dim", "Rule: what's routine, specific enough for a command to show it"),
      ...(this.#rule.focused
        ? this.#rule.render(INNER)
        : [theme.fg("muted", truncateToWidth(`  ${this.#rule.getValue()}`, INNER, "…"))]),
    ];
    if (this.#mode === "confirm") {
      lines.push("", theme.fg("warning", "Save this rule? y/N"));
    }
    return lines;
  }

  #editingProject(): string | undefined {
    const existing = this.#local.find((r) => r.id === this.#editing);
    return existing?.scope === "project" && existing.project ? existing.project : this.#opts.project;
  }

  #rowLabel(row: Row, active: boolean): string {
    const { theme } = this.#opts;
    const color = active ? "accent" : "text";
    if (row.kind === "add") return theme.fg(color, "+ Add rule");
    if (row.kind === "recent") return theme.fg(color, truncateToWidth(row.item.text, INNER - 2, "…"));
    const tags: string[] = [];
    if (row.kind === "kempt") tags.push("kempt");
    if (row.kind === "local" && row.rule.scope === "project" && row.rule.project !== this.#opts.project) {
      tags.push(this.#projectName(row.rule.project));
    }
    if (row.kind === "local" && !row.rule.enabled) tags.push("off");
    const tag = tags.length ? ` (${tags.join(", ")})` : "";
    const text = truncateToWidth(row.rule.rule, INNER - 2 - tag.length, "…");
    const off = row.kind === "local" && !row.rule.enabled;
    return (off ? theme.fg("dim", text) : theme.fg(color, text)) + theme.fg("dim", tag);
  }

  #detail(row: Row | undefined): string[] {
    const { theme } = this.#opts;
    if (!row) return this.#tab === "recent" ? [theme.fg("dim", "Actions Jev deferred that you approved show up here, to make routine.")] : [];
    if (row.kind === "add") {
      return this.#tab === "project"
        ? [theme.fg("dim", this.#opts.project
            ? `Add a rule for ${this.#projectName(this.#opts.project)} and its worktrees.`
            : "Not in a git repository: Project rules can't be added here.")]
        : [theme.fg("dim", "Add a rule for every project on this machine.")];
    }
    if (row.kind === "recent") {
      return [
        theme.fg("dim", `You approved (the agent's command, as written) at ${row.item.at.slice(11, 16)}Z:`),
        theme.fg("muted", truncateToWidth(row.item.text, INNER, "…")),
        theme.fg("dim", "Enter drafts a rule from it: rewrite it as the general rule you mean."),
      ];
    }
    const lines = wrapTextWithAnsi(row.rule.rule, INNER).slice(0, DETAIL_LINES - 1).map((l) => theme.fg("text", l));
    if (row.kind === "kempt") {
      lines.push(theme.fg("dim", `${row.rule.scope ? `in ${row.rule.scope}` : "every project"} · managed in kempt`));
      return lines;
    }
    const where = row.rule.scope === "user"
      ? "every project"
      : `${this.#projectName(row.rule.project)}${row.rule.project === this.#opts.project ? " (this project)" : ""}`;
    const state = row.rule.enabled ? "on" : "off";
    const added = row.rule.addedAt ? ` · added ${row.rule.addedAt.slice(0, 16).replace("T", " ")}Z` : "";
    lines.push(theme.fg("dim", `${where} · ${state}${added}`));
    return lines;
  }

  #footer(): string {
    if (this.#mode === "edit") return "tab switch field · ←→ scope · enter save · esc back";
    if (this.#mode === "confirm") return "y confirm · any other key cancels";
    if (this.#tab === "recent") return "←→ tabs · ↑↓ select · enter make a rule · esc close";
    return "←→ tabs · ↑↓ select · enter edit · space on/off · d remove · esc close";
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
