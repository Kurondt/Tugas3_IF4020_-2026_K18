"""Test consumer orchestration with the real CLI and a local Docker adapter.

This deliberately does not claim to validate containers, registry pulls or mounts.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('consumer', Path(__file__).with_name('consumer.py'))
consumer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)
REAL_RUN = subprocess.run


class ConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.temp.name) / 'norsign'
        REAL_RUN(['go', 'build', '-o', str(cls.binary), './cmd/norsign'], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_orchestration_all_profiles(self):
        for profile, key in [('ed25519', 'ed25519'), ('ecdsa-p256-sha256', 'ecdsa_p256'), ('rsa-pss-sha256', 'rsa_pss_3072')]:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / 'results'
                key_text = Path(f'tests/fixture/testdata/keys/{key}.key.pem').read_text()
                secret_paths = []

                def docker(cmd, **kwargs):
                    self.assertEqual(cmd[0], 'docker')
                    if cmd[1] == 'pull':
                        return subprocess.CompletedProcess(cmd, 0)
                    self.assertIn('--network', cmd)
                    self.assertEqual(cmd[cmd.index('--network') + 1], 'none')
                    self.assertIn('--user', cmd)
                    self.assertNotIn('-t', cmd)
                    mounts = {}
                    image_index = next(i for i, value in enumerate(cmd) if value.startswith('ghcr.io/'))
                    for i, value in enumerate(cmd[:image_index]):
                        if value == '--mount':
                            fields = dict(x.split('=', 1) for x in cmd[i+1].split(',') if '=' in x)
                            mounts[fields['dst']] = fields['src']
                            if fields['dst'] == '/run/signing.key.pem':
                                secret_paths.append(Path(fields['src']))
                                self.assertEqual(Path(fields['src']).stat().st_mode & 0o777, 0o600)
                    args = []
                    for arg in cmd[image_index+1:]:
                        for destination, source in sorted(mounts.items(), key=lambda pair: -len(pair[0])):
                            if arg == destination or arg.startswith(destination + '/'):
                                arg = source + arg[len(destination):]
                                break
                        args.append(arg)
                    if args[0] == 'verify':
                        self.assertTrue(all(not path.exists() for path in secret_paths))
                    return REAL_RUN([str(self.binary)] + args, **kwargs)

                argv = ['consumer.py', '--image', 'ghcr.io/kurondt/norsign@sha256:' + 'a'*64,
                        '--profile', profile, '--out', str(output)]
                with patch.object(sys, 'argv', argv), patch.dict(os.environ, {'CONSUMER_SIGNING_KEY': key_text}), patch.object(subprocess, 'run', docker), contextlib.redirect_stdout(io.StringIO()):
                    consumer.main()
                data = json.loads((output / 'summary.json').read_text())
                self.assertEqual([item['scenario'] for item in data['scenarios']], ['C01', 'C02', 'C03', 'C04', 'C05'])
                self.assertTrue((output / 'C01/deployment-approved').exists())
                for scenario in ['C02', 'C03', 'C04']:
                    self.assertFalse((output / scenario / 'deployment-approved').exists())
                self.assertFalse(list(output.rglob('*.key.pem')))
                self.assertTrue(all(not path.exists() for path in secret_paths))

    def test_reject_tag_only_image(self):
        with patch.object(sys, 'argv', ['consumer.py', '--image', 'ghcr.io/kurondt/norsign:1.0.0', '--profile', 'ed25519']), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                consumer.main()
            self.assertEqual(caught.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
