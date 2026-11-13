"""Native platform tests; no mocked Windows locking or filesystem operations."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

from common import Fixture, ROOT, br, cm
from storage import atomic_write_bytes, atomic_write_json, locked, read_json, safe_path, validate_windows_path
from runtime_support import load_timezone
from package_skill import build_package


def hold_lock(path, ready):
    with locked(path):
        ready.set()
        time.sleep(15)


class TestPortableStorage(Fixture):
    def test_nested_lock_is_reentrant(self):
        path = self.root / 'nested.lock'
        with locked(path), locked(path, timeout=0):
            atomic_write_json(self.root / 'value.json', {'result': 'ok'})
        self.assertEqual(read_json(self.root / 'value.json'), {'result': 'ok'})

    def test_process_contention_timeout_and_termination_release(self):
        ctx = multiprocessing.get_context('spawn')
        ready = ctx.Event()
        path = self.root / 'worker.lock'
        worker = ctx.Process(target=hold_lock, args=(path, ready))
        worker.start()
        try:
            self.assertTrue(ready.wait(10))
            with self.assertRaises(TimeoutError):
                with locked(path, timeout=0.1):
                    self.fail('Two processes entered the same lock')
        finally:
            worker.terminate(); worker.join(10); worker.close()
        with locked(path, timeout=2):
            self.assertTrue(path.exists())

    def test_thread_contention_timeout(self):
        path = self.root / 'thread.lock'
        errors = []
        with locked(path):
            def wait():
                try:
                    with locked(path, timeout=0.05):
                        errors.append('unexpected acquisition')
                except TimeoutError:
                    errors.append('timeout')
            thread = threading.Thread(target=wait); thread.start(); thread.join(5)
        self.assertEqual(errors, ['timeout'])

    def test_bad_lock_timeouts(self):
        for value in (-1, float('nan'), float('inf')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                with locked(self.root / 'bad.lock', timeout=value):
                    pass

    def test_exception_releases_lock(self):
        path = self.root / 'error.lock'
        with self.assertRaises(RuntimeError), locked(path):
            raise RuntimeError('synthetic failure')
        with locked(path, timeout=0):
            pass

    def test_utf8_bom_input_and_untranslated_binary_output(self):
        path = self.root / '中文 空格.json'
        path.write_bytes(b'\xef\xbb\xbf' + '{"name":"中文"}'.encode())
        self.assertEqual(read_json(path)['name'], '中文')
        content = bytes(range(256)) + b'\n\r\n'
        atomic_write_bytes(path, content)
        self.assertEqual(path.read_bytes(), content)
        self.assertPrivatePath(path)

    def test_failed_replace_preserves_destination_and_cleans_temp(self):
        path = self.root / 'existing.json'; atomic_write_json(path, {'old': True})
        with patch('storage._replace', side_effect=OSError('synthetic failure')), self.assertRaises(OSError):
            atomic_write_json(path, {'old': False})
        self.assertEqual(read_json(path), {'old': True})
        self.assertEqual(list(self.root.glob('.write-*')), [])

    def test_private_permissions_after_replacement(self):
        path = self.root / 'private.json'
        atomic_write_json(path, {'one': 1}); atomic_write_json(path, {'two': 2})
        self.assertPrivatePath(path); self.assertPrivatePath(path.parent, directory=True)

    def test_windows_unsafe_path_syntax_is_rejected(self):
        paths = ['C:relative', r'\\server\share\case.json', r'\\?\C:\case.json',
                 r'\\.\NUL', r'C:\data\file:stream', r'C:\data\name.',
                 r'C:\data\name ', r'C:\data\NUL.json', r'C:\data\COM1',
                 r'C:\data\lpt².txt', r'C:\data\a?b', 'C:\\data\\a\x00b']
        for value in paths:
            with self.subTest(path=value), self.assertRaises(ValueError):
                validate_windows_path(value)

    def test_windows_valid_path_syntax(self):
        for value in [r'C:\Users\品牌 员工\资料.json', 'D:/品牌/图片.png', r'folder\input.json', 'C:/', r'..\profile.json']:
            validate_windows_path(value)

    def test_named_timezone_dst_and_workday_estimate(self):
        new_york = load_timezone('America/New_York')
        self.assertEqual(datetime(2026, 1, 15, tzinfo=new_york).utcoffset(), timedelta(hours=-5))
        self.assertEqual(datetime(2026, 7, 15, tzinfo=new_york).utcoffset(), timedelta(hours=-4))
        self.channel()
        state = cm.record_counter_notice(self.case, 'host', '2026-10-30T12:00:00Z', 'Synthetic review',
            provider_received_at='2026-10-30T12:00:00Z', provider_timezone='America/New_York', source_ref='synthetic-dst')
        task = state['counter_notices'][0]
        self.assertEqual(task['earliest_restore_estimate'], '2026-11-13T13:00:00Z')

    def test_missing_timezone_has_install_instruction(self):
        from zoneinfo import ZoneInfoNotFoundError
        with patch('runtime_support.ZoneInfo', side_effect=ZoneInfoNotFoundError('missing')):
            with self.assertRaisesRegex(ValueError, 'pip install -r requirements.txt'):
                load_timezone('America/New_York')

    def test_zip_platform_metadata_and_checksums(self):
        path = self.root / 'package.zip'
        build_package(path)
        with zipfile.ZipFile(path) as archive:
            self.assertTrue(all(i.create_system == 3 for i in archive.infolist()))
            self.assertTrue(all('\\' not in n for n in archive.namelist()))
            for line in archive.read('brand-takedown/SHA256SUMS.txt').decode('utf-8').splitlines():
                digest, name = line.split('  ', 1)
                self.assertEqual(hashlib.sha256(archive.read('brand-takedown/' + name)).hexdigest(), digest)

    def test_chinese_path_cli_with_legacy_output_encoding(self):
        home = self.root / '员工 空格'; home.mkdir()
        source = home / '品牌输入.json'
        profile = dict(self.profile); profile.pop('brand_id'); profile['brand_slug'] = 'unicode-brand'
        profile['brand_name'] = '测试品牌'
        source.write_bytes(b'\xef\xbb\xbf' + json.dumps(profile, ensure_ascii=False).encode('utf-8'))
        env = dict(os.environ, PYTHONUTF8='0', PYTHONIOENCODING='cp1252', BRAND_TAKEDOWN_REGISTRY=str(self.registry))
        args = [sys.executable, str(ROOT/'scripts/brand_registry.py'), 'init', '--slug', 'unicode-brand',
                '--data-dir', str(home/'私有 案件'), '--profile-file', str(source)]
        result = subprocess.run(args, env=env, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode('utf-8'))
        self.assertEqual(br.profile_from_dir(home/'私有 案件')['brand_name'], '测试品牌')
        result = subprocess.run([sys.executable,str(ROOT/'scripts/brand_registry.py'),'list'],env=env,capture_output=True,timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('unicode-brand', json.loads(result.stdout.decode('utf-8'))['brands'])

    def test_doctor_checks_selected_directory(self):
        from doctor import diagnose
        result = diagnose(self.root)
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['storage']['lock_backend'], 'msvcrt' if os.name == 'nt' else 'flock')

    def test_doctor_missing_directory_reports_error(self):
        from doctor import diagnose
        result = diagnose(self.root / 'absent')
        self.assertFalse(result['ok'])

    @unittest.skipUnless(os.name == 'nt', 'Native Windows filesystem test')
    def test_windows_case_alias_lock_is_reentrant(self):
        path = self.root / 'MixedCase.lock'
        with locked(path), locked(self.root / 'mixedcase.LOCK', timeout=0):
            pass

    @unittest.skipUnless(os.name == 'nt', 'Native Windows filesystem test')
    def test_windows_junction_is_rejected(self):
        target = self.root/'target'; target.mkdir()
        junction = self.root/'junction'
        result = subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(junction),str(target)],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        try:
            with self.assertRaises(ValueError): safe_path(junction/'state.json')
        finally:
            junction.rmdir()

    @unittest.skipUnless(os.name == 'nt', 'Native Windows filesystem test')
    def test_windows_readonly_destination_is_preserved(self):
        import stat
        path = self.root/'readonly.json'; atomic_write_json(path, {'old': True})
        path.chmod(stat.S_IREAD)
        try:
            with self.assertRaises(PermissionError): atomic_write_json(path, {'old':False})
            self.assertEqual(read_json(path), {'old':True})
        finally:
            path.chmod(stat.S_IWRITE | stat.S_IREAD)
        self.assertEqual(list(self.root.glob('.write-*')), [])
