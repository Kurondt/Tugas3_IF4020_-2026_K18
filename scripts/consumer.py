#!/usr/bin/env python3
"""Exercise a digest-pinned image on a clean runner; never build/install jarsign."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', required=True)
    parser.add_argument('--profile', choices=['ed25519', 'ecdsa-p256-sha256', 'rsa-pss-sha256'], required=True)
    parser.add_argument('--out', default='consumer-results')
    args = parser.parse_args()
    if not re.fullmatch(r'ghcr\.io/kurondt/jarsign@sha256:[0-9a-f]{64}', args.image):
        parser.error('--image must be pinned by sha256 digest')
    root = Path(args.out).resolve()
    if root.exists():
        raise RuntimeError('output directory must not already exist')
    root.mkdir(parents=True)
    trust = Path('ci/trust.json').resolve()
    subprocess.run(['docker', 'pull', '--platform', 'linux/amd64', args.image], check=True)
    base = ['docker', 'run', '--rm', '--network', 'none', '--user', f'{os.getuid()}:{os.getgid()}']
    summary = []

    def invoke(name, mounts, command):
        cmd = base.copy()
        for source, destination, readonly in mounts:
            cmd += ['--mount', f'type=bind,src={source},dst={destination}' + (',readonly' if readonly else '')]
        result = subprocess.run(cmd + [args.image] + command, capture_output=True, text=True)
        (root / f'{name}.stdout').write_text(result.stdout)
        (root / f'{name}.stderr').write_text(result.stderr)
        (root / f'{name}.exitcode').write_text(str(result.returncode) + '\n')
        return result

    c01 = root / 'C01'
    c01.mkdir()
    payload = b'release payload for jarsign consumer pipeline\n'
    artifact = c01 / 'contoh-app.zip'
    artifact.write_bytes(payload)
    secret = os.environ.pop('CONSUMER_SIGNING_KEY', '')
    if not secret.strip():
        raise RuntimeError('CONSUMER_SIGNING_KEY must contain the configured test private key')
    fd, temporary = tempfile.mkstemp(prefix='jarsign-signing-', suffix='.pem')
    try:
        with os.fdopen(fd, 'w') as file:
            file.write(secret)
        secret = None
        os.chmod(temporary, 0o600)
        signed = invoke('C01-sign', [(c01, '/work', False), (temporary, '/run/signing.key.pem', True)],
                        ['sign', '--file', '/work/contoh-app.zip', '--key', '/run/signing.key.pem',
                         '--package', 'contoh-app', '--version', '1.0.0', '--out', '/work/release.json'])
        if signed.returncode != 0:
            raise RuntimeError(f'sign failed with exit {signed.returncode}; see sanitized stderr')
    finally:
        Path(temporary).unlink(missing_ok=True)

    def verify(scenario, directory, trusted, expected_status, expected_code, filename='contoh-app.zip'):
        result = invoke(scenario + '-verify', [(directory, '/work', True), (trusted, '/trust.json', True)],
                        ['verify', '--file', '/work/' + filename, '--bundle', '/work/release.json',
                         '--trust-store', '/trust.json', '--package', 'contoh-app', '--version', '1.0.0', '--json'])
        data = json.loads(result.stdout)
        marker = directory / 'deployment-approved'
        # This is the gate under test. Negative scenarios run this same gate.
        if result.returncode == 0 and data.get('valid') is True and data.get('status') == 'OK':
            verified = directory / filename
            if hashlib.sha256(verified.read_bytes()).hexdigest() != hashlib.sha256(payload).hexdigest():
                raise RuntimeError('deployment artifact differs from the expected release')
            marker.write_text('verified release deployment simulated\n')
        if result.returncode != expected_code or data.get('status') != expected_status:
            raise RuntimeError(f'{scenario}: expected {expected_status}/{expected_code}, got {data.get("status")}/{result.returncode}')
        if data.get('valid') is not (expected_code == 0) or marker.exists() != (expected_code == 0):
            raise RuntimeError(f'{scenario}: incorrect deployment gate')
        summary.append({'scenario': scenario, 'status': data['status'], 'exit_code': result.returncode,
                        'deployment_marker': marker.exists()})

    verify('C01', c01, trust, 'OK', 0)
    for scenario in ['C02', 'C03', 'C04']:
        directory = root / scenario
        directory.mkdir()
        shutil.copyfile(c01 / 'release.json', directory / 'release.json')
        (directory / 'contoh-app.zip').write_bytes(payload)
        trusted = trust
        filename = 'contoh-app.zip'
        status, code = 'ARTIFACT_MISMATCH', 1
        if scenario == 'C02':
            changed = bytearray(payload)
            changed[0] ^= 1
            (directory / filename).write_bytes(changed)
        elif scenario == 'C03':
            trusted = directory / 'empty-trust.json'
            trusted.write_text('{"schema":"minisign-trust/v1","keys":[]}\n')
            status = 'KEY_NOT_TRUSTED'
        else:
            filename, status, code = 'missing.zip', 'INPUT_ERROR', 2
        verify(scenario, directory, trusted, status, code, filename)

    c05 = root / 'C05'
    c05.mkdir()
    mounts = [(c05, '/work', False)]
    try:
        commands = [('--version', ['--version']), ('--help', ['--help']),
                    ('keygen', ['keygen', '--algorithm', args.profile, '--out', '/work/offline']),
                    ('trust-add', ['trust', 'add', '--key', '/work/offline.pub.pem', '--package', 'offline-app', '--store', '/work/trust.json']),
                    ('trust-list', ['trust', 'list', '--store', '/work/trust.json'])]
        for name, command in commands:
            result = invoke('C05-' + name, mounts, command)
            if result.returncode != 0:
                raise RuntimeError(f'C05 {name}: exit {result.returncode}')
        data = json.loads((c05 / 'trust.json').read_text())
        result = invoke('C05-trust-remove', mounts, ['trust', 'remove', '--keyid', data['keys'][0]['keyid'], '--store', '/work/trust.json'])
        if result.returncode != 0:
            raise RuntimeError('C05 trust remove failed')
    finally:
        (c05 / 'offline.key.pem').unlink(missing_ok=True)
    summary.append({'scenario': 'C05', 'status': 'OK', 'exit_code': 0,
                    'network': 'none', 'tty': False, 'uid': os.getuid(), 'gid': os.getgid()})
    (root / 'summary.json').write_text(json.dumps({'image': args.image, 'profile': args.profile, 'scenarios': summary}, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
