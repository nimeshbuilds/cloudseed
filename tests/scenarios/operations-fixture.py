#!/usr/bin/env python3
"""Seed only the isolated scenario's saved config, never cloud resources."""
import json
import os
from pathlib import Path

home = Path(os.environ['CLOUDSEED_HOME'])
if 'cs-scenario-' not in str(home):
    raise SystemExit('This fixture requires the isolated scenario home.')
directory = home / 'envs/aws-review'
directory.mkdir(parents=True, exist_ok=True)
(directory / 'config.json').write_text(json.dumps({
    'cloud': 'aws', 'env': 'review', 'name': 'review', 'region': 'us-west-2',
    'network_cidr': '10.42.0.0/16', 'allowed_ssh_cidrs': ['203.0.113.4/32'],
    'vars': {'enable_kubernetes': True}, 'extra_vars': {},
}))
print('Saved fixture aws-review; no infrastructure was created.')
