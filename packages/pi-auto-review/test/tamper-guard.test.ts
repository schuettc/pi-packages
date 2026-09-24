import assert from "node:assert/strict";
import test from "node:test";
import { reviewerTamperingHardDeny } from "../src/review/guards.ts";

const D = "~/.pi/agent/extensions/pi-auto-review";

test("bash writes to the reviewer's config, rules or code are hard-denied", () => {
  for (const command of [
    `echo '{"rules":[]}' > ${D}/rules.json`,
    `echo x >> $HOME/.pi/agent/extensions/pi-auto-review/rules.json`,
    `cp /tmp/r.json ${D}/rules.json`,
    `mv /tmp/c ${D}/config.json`,
    `jq '.reviewer="none"' ${D}/config.json > /tmp/c && mv /tmp/c ${D}/config.json`,
    `ln -sf /tmp/evil.json ${D}/rules.json`,
    `D=${D}; printf x | tee $D/rules.json`,
    `cd ${D} && echo x > rules.json`,
    `sed -i '' 's/jev/none/' ${D}/config.json`,
    `rm -f /Users/court/.pi/agent/extensions/pi-auto-review/policy-audit.sqlite`,
    `python3 -c "open('/Users/court/.pi/agent/extensions/pi-auto-review/rules.json','w').write('x')"`,
    `python3 - <<'PY'\nfrom pathlib import Path\nPath('${D}/rules.json').write_text('{}')\nPY`,
    `node -e "require('fs').writeFileSync(process.env.HOME+'/.pi/agent/extensions/pi-auto-review/rules.json','{}')"`,
    `sqlite3 ${D}/policy-audit.sqlite "DELETE FROM decisions"`,
    `sed -i '' 's/0.55/0.1/' ~/.pi/agent/npm/node_modules/@schuettc/pi-auto-review/src/review/jev-reviewer.ts`,
  ]) {
    assert.equal(reviewerTamperingHardDeny(command)?.rule, "security-control-tampering", command);
  }
});

test("reading the reviewer's files, and unrelated writes, are not hard-denied", () => {
  for (const command of [
    `cat ${D}/rules.json`,
    `jq -c '{reviewer, jev: .reviewers.jev}' ${D}/config.json`,
    `jq -r .version ~/.pi/agent/npm/node_modules/@schuettc/pi-auto-review/package.json 2>/dev/null`,
    `sed -n '1,40p' ~/.pi/agent/npm/node_modules/@schuettc/pi-auto-review/src/index.ts`,
    `grep -rn jev ${D} 2>&1 | head`,
    `ls -la ${D}/ >&2`,
    `sqlite3 ${D}/policy-audit.sqlite "SELECT count(*) FROM decisions"`,
    `node -p "require('${D}/config.json').reviewer"`,
    `echo hi > /tmp/notes.txt`,
    `cp a.json b.json`,
  ]) {
    assert.equal(reviewerTamperingHardDeny(command), undefined, command);
  }
});
