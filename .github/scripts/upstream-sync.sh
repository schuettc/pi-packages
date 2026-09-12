#!/usr/bin/env bash
# Rebase our fork's patch stack onto upstream/main and, on a clean rebase,
# publish the next <upstream-base>-schuettc.N of packages/pi-auto-review to npm.
# On conflicts: abort, open a tracking issue, and FAIL the job (exit 1) so the
# red run + issue email are the signal. Invoked by .github/workflows/upstream-sync.yml.
#
# Reharden (2026-09-22, see tools-ops audit 2026-09-22-fork-publish-sync-audit):
#   - The committed patch carries ONLY genuine source patches + CI. ALL packaging
#     metadata (scoped name, -schuettc.N version, repo/homepage) is applied at
#     publish time in the isolated copy, never committed. So upstream's
#     every-release version/name/lockfile churn can no longer conflict; only a
#     genuine overlap on our source patches stops the pipeline.
#   - A conflict opens a tracking issue AND fails the job (exit 1) so the red run
#     + issue email are the signal.
set -euo pipefail

PKG="@schuettc/pi-auto-review"
PKGDIR="packages/pi-auto-review"
UPSTREAM_URL="https://github.com/erichll/pi-packages.git"
BRANCH="schuettc-publish"
FORCE="${1:-false}"

git config user.name "schuettc-fork-bot"
git config user.email "actions@github.com"

git remote add upstream "$UPSTREAM_URL" 2>/dev/null || git remote set-url upstream "$UPSTREAM_URL"
git fetch upstream main --quiet

base="$(git merge-base HEAD upstream/main)"
ahead="$(git rev-list --count "${base}..upstream/main")"
echo "upstream/main is ${ahead} commit(s) ahead of our base ${base}"

if [ "$ahead" -eq 0 ] && [ "$FORCE" != "true" ]; then
  echo "In sync; nothing to publish."
  exit 0
fi

if [ "$ahead" -gt 0 ]; then
  echo "Rebasing our patch stack onto upstream/main..."
  if ! git rebase upstream/main; then
    upstream_log="$(git --no-pager log --oneline "${base}..upstream/main")"
    git rebase --abort || true
    title="upstream sync: manual rebase needed (${ahead} new upstream commit(s))"
    body="$(printf 'Automated rebase of %s onto erichll/main hit conflicts on genuine source patches and was aborted — nothing was published.\n\nNew upstream commits:\n\n```\n%s\n```\n\nResolve locally: rebase %s onto upstream/main, force-push, then re-run the upstream-sync workflow (or let the next daily run pick it up).' "$BRANCH" "$upstream_log" "$BRANCH")"
    if [ "$(gh issue list --state open --search "$title in:title" --json number --jq 'length')" = "0" ]; then
      gh issue create --title "$title" --body "$body" \
        || echo "::warning::Could not open tracking issue; conflicts still need manual resolution."
    else
      echo "A conflict issue is already open; skipping duplicate."
    fi
    echo "::error::upstream-sync rebase conflicted; published nothing. See the tracking issue."
    exit 1
  fi
fi

upstream_ver="$(git show "upstream/main:${PKGDIR}/package.json" | node -pe 'JSON.parse(require("fs").readFileSync(0,"utf8")).version')"
echo "upstream base version: ${upstream_ver}"

published="$(npm view "$PKG" versions --json 2>/dev/null || echo '[]')"
next_n="$(BASE="$upstream_ver" PUBLISHED="$published" node -e '
  const base = process.env.BASE;
  let v = [];
  try { v = JSON.parse(process.env.PUBLISHED); } catch (_) {}
  if (!Array.isArray(v)) v = [v];
  const re = new RegExp("^" + base.replace(/[.]/g, "\\.") + "-schuettc\\.(\\d+)$");
  let max = 0;
  for (const s of v) { const m = re.exec(s); if (m) max = Math.max(max, parseInt(m[1], 10)); }
  process.stdout.write(String(max + 1));
')"
new_ver="${upstream_ver}-schuettc.${next_n}"
echo "publishing new version: ${new_ver}"

# Publish from an isolated copy: `npm publish --provenance` from inside the
# monorepo builds the arborist tree and hits a null workspace self-node. A
# standalone copy has no workspace context. Provenance reads the build identity
# from the CI OIDC token + GITHUB_* env, so the copy is fine. ALL packaging
# metadata is stamped HERE only — never committed to the branch — so the next
# upstream release replays our source patches with zero metadata conflicts.
pubdir="$(mktemp -d)"
cp -R "$PKGDIR/." "$pubdir/"
PKG="$PKG" VER="$new_ver" node -e '
  const fs=require("fs"), f=process.argv[1], p=JSON.parse(fs.readFileSync(f));
  p.name = process.env.PKG;
  p.version = process.env.VER;
  p.repository = { type: "git", url: "git+https://github.com/schuettc/pi-packages.git", directory: "packages/pi-auto-review" };
  p.homepage = "https://github.com/schuettc/pi-packages/tree/main/packages/pi-auto-review";
  fs.writeFileSync(f, JSON.stringify(p, null, 2) + "\n");
' "$pubdir/package.json"
( cd "$pubdir" && npm publish --provenance --access public --tag latest )
rm -rf "$pubdir"

# Keep schuettc-publish current (rebased onto upstream, our source patches on
# top) so tomorrow's run sees ahead=0. The branch stays upstream-named; the
# scoped name + -schuettc.N live only on npm + the tag.
git push --force-with-lease origin "HEAD:${BRANCH}"
git tag "pi-auto-review-v${new_ver}"
git push origin "pi-auto-review-v${new_ver}"

echo "Published ${PKG}@${new_ver}; pushed ${BRANCH} + tag pi-auto-review-v${new_ver}."
