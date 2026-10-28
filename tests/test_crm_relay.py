"""Exercise rule generation without root, network or host firewall changes."""
import importlib.util
import pathlib
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'relay', pathlib.Path(__file__).parents[1] / 'ops/scripts/vpn-crm-relay.py')
relay = importlib.util.module_from_spec(spec)
# Windows lacks fcntl. Tests exercise pure rule generation, never the Linux CLI lock.
try:
    import fcntl
except ImportError:
    with patch.dict(sys.modules, {'fcntl': types.ModuleType('fcntl')}):
        spec.loader.exec_module(relay)
else:
    spec.loader.exec_module(relay)


class Firewall:
    def __init__(self):
        self.chains = {('nat', 'PREROUTING'): [('existing-docker-nat',)],
                       ('nat', 'POSTROUTING'): [('existing-masquerade',)],
                       ('filter', 'DOCKER-USER'): [('existing-user-rule',)]}

    def __call__(self, table, action, chain, *args, check=True):
        key = table, chain
        code = 0
        if action == '-S':
            code = int(key not in self.chains)
        elif action == '-N':
            self.chains[key] = []
        elif action == '-F':
            self.chains[key] = []
        elif action == '-X':
            del self.chains[key]
        elif action == '-C':
            code = int(tuple(args) not in self.chains.get(key, []))
        elif action == '-A':
            self.chains[key].append(tuple(args))
        elif action == '-I':
            self.chains[key].insert(int(args[0]) - 1, tuple(args[1:]))
        elif action == '-D':
            self.chains[key].remove(tuple(args))
        else:
            raise AssertionError(action)
        if check and code:
            raise RuntimeError('Missing chain/rule')
        return subprocess.CompletedProcess([], code, '', '')


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.fw = Firewall()
        self.rules = patch.object(relay, 'ipt', self.fw)
        self.forward = patch.object(relay.pathlib.Path, 'read_text', return_value='1\n')
        self.rules.start()
        self.forward.start()
        self.addCleanup(self.rules.stop)
        self.addCleanup(self.forward.stop)

    def test_apply_is_idempotent_and_preserves_existing_rules(self):
        relay.apply()
        expected = {k: list(v) for k, v in self.fw.chains.items()}
        relay.apply()
        self.assertEqual(self.fw.chains, expected)
        self.assertIn(('existing-docker-nat',), self.fw.chains['nat', 'PREROUTING'])
        self.assertEqual(len(self.fw.chains['filter', 'VPNCRM_FWD']), 6)

    def test_only_selected_ports_and_original_destination_are_forwarded(self):
        relay.apply()
        dnat = self.fw.chains['nat', 'VPNCRM_DNAT']
        self.assertEqual([r[r.index('--dport') + 1] for r in dnat], ['14443', '51820', '22067'])
        for r in self.fw.chains['filter', 'VPNCRM_FWD']:
            self.assertEqual(r[r.index('--ctorigdst') + 1], relay.PUBLIC)
            self.assertIn('--ctdir', r)
        for r in self.fw.chains['nat', 'VPNCRM_SNAT']:
            self.assertIn('--ctorigdstport', r)

    def test_remove_is_idempotent_and_preserves_unrelated_rules(self):
        initial = {k: list(v) for k, v in self.fw.chains.items()}
        relay.apply()
        relay.remove()
        relay.remove()
        self.assertEqual(initial, self.fw.chains)

    def test_forwarding_disabled_fails_without_changes(self):
        initial = {k: list(v) for k, v in self.fw.chains.items()}
        with patch.object(relay.pathlib.Path, 'read_text', return_value='0\n'):
            with self.assertRaises(RuntimeError):
                relay.apply()
        self.assertEqual(initial, self.fw.chains)

    def test_error_during_rule_creation_removes_owned_rules(self):
        original_append = relay.append

        def fail(table, chain, args):
            if chain == 'VPNCRM_SNAT':
                raise RuntimeError('Injected failure')
            original_append(table, chain, args)

        initial = {k: list(v) for k, v in self.fw.chains.items()}
        with patch.object(relay, 'append', fail):
            with self.assertRaises(RuntimeError):
                relay.apply()
        self.assertEqual(initial, self.fw.chains)


if __name__ == '__main__':
    unittest.main()
