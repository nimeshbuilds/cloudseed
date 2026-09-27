"""Exercise the real usage panel with a small DOM and controlled report responses."""
from __future__ import annotations

import json
import shutil
import subprocess
import unittest

from tests.test_wave2_web import JS, js_def


HARNESS = r"""
const requests = [], actions = [], downloads = [], timers = [];
class Element {
  constructor(tag, attrs, children) {
    this.tag = tag; this.attrs = attrs; Object.assign(this, attrs);
    this.kids = children.flat(Infinity).filter(x => x !== null && x !== undefined && x !== false);
    this.disabled = Boolean(attrs.disabled); this.isConnected = true;
    this.value = attrs.value ?? (tag === 'select' ? this.kids[0]?.value : undefined);
  }
  append(...children) { this.kids.push(...children.flat(Infinity)); }
  replaceChildren(...children) { this.kids = children.flat(Infinity); }
  get textContent() { return this.kids.map(x => x instanceof Element ? x.textContent : String(x)).join(' '); }
  set textContent(value) { this.kids = [value]; }
  querySelectorAll(tag) { return walk(this).slice(1).filter(x => x.tag === tag); }
  click() { if (this.tag === 'a') downloads.push({href: this.href, name: this.download}); }
}
const el = (tag, attrs = {}, ...children) => new Element(tag, attrs, children);
const walk = root => [root, ...root.kids.filter(x => x instanceof Element).flatMap(walk)];
const button = (root, label) => walk(root).find(x => x.tag === 'button' && x.textContent === label);
const select = (root, label) => walk(root).find(x => x.tag === 'select' && x.attrs['aria-label'] === label);
const explainBtn = () => null;
const fmtTime = x => x;
const run = (...args) => actions.push(args);
const setTimeout = fn => { timers.push(fn); return timers.length; };
let blob;
class Blob { constructor(parts) { this.parts = parts; } }
const URL = { createObjectURL: value => { blob = value; return 'blob:synthetic'; }, revokeObjectURL: () => {} };
const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
const click = async (root, label) => {
  const target = button(root, label);
  if (!target || target.disabled) throw new Error('Button unavailable: ' + label);
  target.onclick(); await flush();
};
const choose = async (root, label, value) => {
  const target = select(root, label); target.value = value; target.onchange(); await flush();
};
const sample = (id, next = null) => ({
  generated_at: '2026-09-27T00:00:00Z',
  summary: { known_usage: { input_tokens: 12, output_tokens: 4, cache_read_tokens: 2, cache_write_tokens: 1 } },
  coverage: { total_records: 20, next_offset: next, reasons: [] },
  runs: [{ id, agent: 'claude', model: 'observed-model', models: ['observed-model'], model_provenance: 'provider',
    started_at: '2026-09-27T00:00:00Z', status: 'complete', usage: {input_tokens: 12, output_tokens: 4}, reasons: [] }],
  mcp: {calls: [], call_count: 0, reason: 'Host model tokens are unavailable.'},
  ccusage: {installed: false, reason: 'Run cs usage install.'}
});
"""


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class UsagePanelTests(unittest.TestCase):
    def node(self, api, exercise):
        code = HARNESS + "\n" + api + "\n" + js_def(JS, "function usagePanel(")
        code += "\n(async () => {\n" + exercise + "\n})().catch(e => { console.error(e); process.exit(1); });"
        proc = subprocess.run(["node", "-e", code], capture_output=True, text=True, timeout=15)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout.strip().splitlines()[-1])

    def test_missing_tokens_and_cost_remain_unavailable_with_reasons(self):
        result = self.node(r"""
const api = async path => {
  const result = sample('partial-fixture');
  result.summary.known_usage.input_tokens = null;
  result.runs[0].usage = {input_tokens: null, output_tokens: null};
  result.runs[0].status = 'partial';
  result.runs[0].reasons = ['Provider omitted a token breakdown.'];
  result.ccusage = {installed: true, estimated_cost_usd: null, basis: 'Unknown model price; not an invoice.'};
  return result;
};
""", r"""
const panel = usagePanel(); await timers.shift()();
await choose(panel, 'Usage reporting engine', 'ccusage');
console.log(JSON.stringify({text: panel.textContent, cells: walk(panel).filter(x => x.tag === 'td').map(x => x.textContent)}));
""")
        self.assertIn("Provider omitted a token breakdown.", result["text"])
        self.assertIn("Estimate unavailable", result["text"])
        self.assertNotIn("$0.000000", result["text"])
        self.assertEqual(result["cells"][3:5], ["unavailable", "unavailable"])

    def test_pagination_uses_returned_offset_and_filter_resets_history(self):
        result = self.node(r"""
const api = async path => {
  requests.push(path); const query = new URLSearchParams(path.split('?')[1]);
  return sample(query.get('agent') || 'all', query.get('offset') === '0' ? 3 : null);
};
""", r"""
const panel = usagePanel(); await timers.shift()();
await click(panel, 'Next');
const lastPage = {nextDisabled: button(panel, 'Next').disabled, previousDisabled: button(panel, 'Previous').disabled};
await click(panel, 'Previous');
await click(panel, 'Next');
await choose(panel, 'Filter usage by agent', 'claude');
console.log(JSON.stringify({requests, lastPage, resetPrevious: button(panel, 'Previous').disabled}));
""")
        self.assertIn("offset=3", result["requests"][1])
        self.assertIn("offset=0", result["requests"][2])
        self.assertIn("offset=0", result["requests"][-1])
        self.assertIn("agent=claude", result["requests"][-1])
        self.assertEqual(result["lastPage"], {"nextDisabled": True, "previousDisabled": False})
        self.assertTrue(result["resetPrevious"])

    def test_missing_engine_keeps_explicit_unconfirmed_install_action(self):
        result = self.node(r"""
const api = async path => {
  if (path.includes('engine=ccusage')) throw new Error('Pinned ccusage is not installed; run cs usage install.');
  return sample('native-fixture');
};
""", r"""
const panel = usagePanel(); await timers.shift()();
await choose(panel, 'Usage reporting engine', 'ccusage');
await click(panel, 'Install ccusage…');
console.log(JSON.stringify({text: panel.textContent, actions, downloadDisabled: button(panel, 'Download this page').disabled}));
""")
        self.assertIn("Could not read usage:", result["text"])
        self.assertEqual(result["actions"], [["cloudseed_usage_install", {}, "install ccusage reporting engine"]])
        self.assertTrue(result["downloadDisabled"])

    def test_download_matches_only_the_current_filtered_page(self):
        result = self.node(r"""
const api = async path => {
  const query = new URLSearchParams(path.split('?')[1]); return sample(query.get('agent') || 'unfiltered', 7);
};
""", r"""
const panel = usagePanel(); await timers.shift()();
await choose(panel, 'Filter usage by agent', 'claude');
await click(panel, 'Download this page');
console.log(JSON.stringify({download: JSON.parse(blob.parts.join('')), downloads}));
""")
        self.assertEqual([row["id"] for row in result["download"]["runs"]], ["claude"])
        self.assertEqual(result["download"]["coverage"]["next_offset"], 7)
        self.assertEqual(result["downloads"], [{"href": "blob:synthetic", "name": "cloudseed-usage.json"}])


if __name__ == "__main__":
    unittest.main()
