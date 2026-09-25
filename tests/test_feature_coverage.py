"""Documentation coverage is an inventory, not an assertion that unrun cloud work passed.

Regenerate the checked manifest with python3 tests/test_feature_coverage.py --write-manifest.
"""
import json
import os
import tempfile
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CLOUDSEED_HOME", tempfile.mkdtemp(prefix="cloudseed-doc-coverage-"))
from cloudseed import mcp, operations, platform
from tests import test_scenarios_docs as scenarios

MANIFEST = ROOT / 'docs/scenarios/feature-coverage.json'
EXAMPLES = ROOT / 'docs/scenarios/interface-examples.json'
GROUP_SCENARIOS = {'basek8s': ['06'], 'scaling': ['06', '13'], 'data': ['07'], 'ai': ['07'], 'agentic': ['07'],
                   'finops': ['15'], 'devsecops': ['06', '10'], 'security': ['06', '10'], 'resilience': ['08', '18'], 'chaos': ['09']}
TOOLS = {
    'setup': 'cloudseed_setup', 'plan': 'cloudseed_plan', 'apply': 'cloudseed_apply', 'destroy': 'cloudseed_destroy',
    'list': 'cloudseed_list', 'status': 'cloudseed_status', 'output': 'cloudseed_output', 'inventory': 'cloudseed_inventory',
    'troubleshoot': 'cloudseed_troubleshoot', 'doctor': 'cloudseed_doctor', 'update-ip': 'cloudseed_update_ip',
    'provision': 'cloudseed_provision', 'ssh': 'cloudseed_ssh', 'k8s': 'cloudseed_k8s', 'env': 'cloudseed_env',
    'node': 'cloudseed_node', 'kubectl': 'cloudseed_kubectl', 'helm': 'cloudseed_helm', 'platform': 'cloudseed_platform',
    'vpn': 'cloudseed_vpn', 'finops': 'cloudseed_finops', 'dr': 'cloudseed_dr', 'chaos': 'cloudseed_chaos',
    'scan': 'cloudseed_scan', 'databricks': 'cloudseed_managed', 'snowflake': 'cloudseed_managed',
    'undo': 'cloudseed_undo', 'explain': 'cloudseed_explain', 'help': 'cloudseed_help', 'skill': 'cloudseed_skill',
}
OP_SCENARIOS = {'health': ['16'], 'network': ['16'], 'profile': ['17'], 'spec-export': ['17'], 'spec-validate': ['17'],
                'spec-diff': ['17'], 'spec-import': ['17'], 'policy-check': ['17'], 'expiry-plan': ['17'], 'expiry-cleanup': ['17'],
                'drift': ['18'], 'upgrade-plan': ['18'], 'upgrade-apply': ['18'], 'recovery-plan': ['18'], 'recovery-test': ['18'],
                'acceptance': ['19'], 'credentials-backend': ['19'], 'release-verify': ['19']}


def manifest():
    coverage = scenarios.coverage()
    commands = []
    for command, subcommand in scenarios.cli_rows():
        tool = TOOLS.get(command)
        if command == 'ops' and subcommand != 'list':
            tool = 'cloudseed_ops_' + subcommand.replace('-', '_')
        boundary = (command in ('install', 'deps', 'enable', 'disable', 'use', 'model', 'agents', 'agentic', 'do', 'mcp', 'ui', 'creds', 'k9s')
                    or command == 'skill' and subcommand in ('list', 'install') or command == 'ops' and subcommand == 'list')
        commands.append({'command': command, 'subcommand': subcommand, 'scenarios': sorted(coverage.get((command, subcommand), [])),
                         'cli': True, 'agent': 'human-bootstrap-or-interactive' if boundary else 'bundled-skill-guided',
                         'mcp_tool': None if boundary else tool,
                         'ui': 'host-bootstrap-or-native-interaction' if boundary else 'typed-action-or-dedicated-page',
                         'notes': 'Authentication, host/service setup and interactive sessions retain human steps; see interfaces-and-coverage.md.' if boundary else 'Use the same selected environment, parameters, approvals and verification as the CLI steps.'})
    return {'schema_version': 1, 'meaning': 'Documented interface and feature coverage; not proof of live cloud deployment or every chart installation.',
            'scenario_count': len(scenarios.scenario_pages()), 'commands': commands,
            'operations': [{'name': name, 'scenarios': OP_SCENARIOS.get(name, []), 'mcp_tool': 'cloudseed_ops_' + name.replace('-', '_'),
                            'ui': 'All actions > Operations & readiness', 'agent': 'bundled-skill-guided'} for name in operations.OPERATIONS],
            'catalog': [{'item': name, 'group': value['group'], 'scenarios': GROUP_SCENARIOS.get(value['group'], []),
                         'mcp_tool': 'cloudseed_platform', 'ui': 'Platform: inspect / plan / install / verify / uninstall',
                         'provider_restrictions': value.get('only', []), 'live_validation': 'item-specific prerequisites and readiness must be verified on your cluster'}
                        for name, value in sorted(platform.CATALOG.items())]}


class FeatureCoverageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = manifest()
        cls.actual = json.loads(MANIFEST.read_text())

    def test_manifest_matches_current_commands_operations_and_every_catalog_item(self):
        self.assertEqual(self.actual, self.expected, 'Regenerate tests/test_feature_coverage.py --write-manifest after documenting new features')
        for section in ('commands', 'operations', 'catalog'):
            for entry in self.actual[section]:
                self.assertTrue(entry['scenarios'], entry)
                if entry.get('mcp_tool'):
                    self.assertIn(entry['mcp_tool'], mcp.TOOLS)
        self.assertEqual(set(GROUP_SCENARIOS), set(platform.GROUPS))
        self.assertEqual(set(OP_SCENARIOS), set(operations.OPERATIONS))

    def test_all_scenarios_have_concrete_agent_mcp_and_ui_instructions(self):
        for page in scenarios.scenario_pages():
            text = page.read_text()
            for marker in ('## Use an agent, MCP or the UI', '**Agent prompt:**', '**MCP', '**UI:**'):
                self.assertIn(marker, text, page.name)
            self.assertRegex(text, r'`cloudseed_[a-z0-9_]+`', page.name)

    def test_starter_tool_arguments_match_real_mcp_schemas(self):
        examples = json.loads(EXAMPLES.read_text())
        self.assertEqual(set(examples), {p.name[:2] for p in scenarios.scenario_pages()})
        for number, row in examples.items():
            tool = mcp.TOOLS[row['tool']]
            _args, problem = mcp.validate_args(tool, row['arguments'])
            self.assertIsNone(problem, (number, problem))
            page = next(scenarios.DOCS.glob(number + '-*.md')).read_text()
            self.assertIn(row['tool'], page)

    def test_new_scenarios_do_not_label_mock_provider_tests_live_cloud_proof(self):
        for page in scenarios.scenario_pages():
            if int(page.name[:2]) >= 16:
                self.assertIn('Locally verified; cloud deployment pending', page.read_text())


if __name__ == '__main__':
    if '--write-manifest' in sys.argv:
        MANIFEST.write_text(json.dumps(manifest(), indent=2) + '\n')
    else:
        unittest.main()
