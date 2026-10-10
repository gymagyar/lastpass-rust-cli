#!/usr/bin/env python3
"""Read-only live CLI verification. Credentials come exclusively from the environment.

Usage: LPASS_TEST_USERNAME=... LPASS_TEST_PASSWORD=... python3 scripts/live_cli_test.py /absolute/path/to/lpass-rs
Only statuses and counts are printed. All CLI stdout/stderr stays in memory, and
an isolated encrypted cache is removed after logout. No remote vault edits occur.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/lpass-rs').resolve())
    username = os.environ['LPASS_TEST_USERNAME']
    password = os.environ['LPASS_TEST_PASSWORD']
    clean_env = os.environ.copy()
    for name in ('LPASS_PASSWORD', 'LPASS_TEST_PASSWORD', 'LPASS_TEST_USERNAME'):
        clean_env.pop(name, None)
    with tempfile.TemporaryDirectory(prefix='lpass-rs-live-') as directory:
        os.chmod(directory, 0o700)

        def run(args, input_text='', reprompt=False, required=True):
            env = clean_env.copy()
            if reprompt:
                env['LPASS_PASSWORD'] = password
            result = subprocess.run(
                [binary, '--data-dir', directory, *args], input=input_text,
                capture_output=True, text=True, env=env, timeout=120,
            )
            if required and result.returncode:
                # Do not print captured output: it can contain secret vault data.
                raise RuntimeError(f'CLI {args[0]} failed with exit code {result.returncode}')
            return result

        logged_in = False
        try:
            run(['login', username, '--password-stdin'], password + '\n')
            logged_in = True
            print('CLI login: PASS', flush=True)
            run(['status', '--quiet'])
            run(['sync'])
            listing = json.loads(run(['ls', '--sync=no', '--json']).stdout)
            assert isinstance(listing, list)
            print(f'CLI sync/load/list JSON: PASS (items={len(listing)})', flush=True)
            if listing:
                item_id = str(listing[0]['id'])
                shown = json.loads(run(['show', '--sync=no', '--json', item_id], reprompt=True).stdout)
                assert shown and str(shown[0]['id']) == item_id
                run(['show', '--sync=no', '--username', item_id], reprompt=True)
                run(['show', '--sync=no', '--password', item_id], reprompt=True)
                print('CLI show JSON/username/password: PASS', flush=True)
            run(['status', '--check', '--quiet'])
            print('CLI remote session check: PASS', flush=True)
            run(['lock'])
            assert run(['status', '--quiet'], required=False).returncode != 0
            run(['unlock', '--password-stdin'], password + '\n')
            restored = json.loads(run(['ls', '--sync=no', '--json']).stdout)
            assert len(restored) == len(listing)
            print('CLI lock/unlock/offline encrypted cache: PASS', flush=True)
            run(['sync'])
            refreshed = json.loads(run(['ls', '--sync=no', '--json']).stdout)
            assert len(refreshed) == len(listing)
            print('CLI repeat sync: PASS', flush=True)
            run(['logout'])
            logged_in = False
            assert not Path(directory, 'session.enc').exists()
            assert not Path(directory, 'vault.enc').exists()
            print('CLI logout/cache cleanup: PASS', flush=True)
        finally:
            if logged_in:
                run(['logout'], required=False)
            run(['logout', '--force'], required=False)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'Live CLI verification failed: {type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)
