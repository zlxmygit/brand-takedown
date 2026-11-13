"""Pinned Public Suffix List updates, checksummed backups and recoverable rollback."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys
import zlib

from safe_http import fetch
from storage import atomic_write_bytes, atomic_write_json, locked, private_dir, read_json, safe_path

ROOT = Path(__file__).resolve().parent.parent
RELATIVE = 'references/public_suffix_list.dat.gz'
MANIFEST = 'docs/source-checksums.json'
MAX_BYTES = 2 * 1024 * 1024


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(value: str, length: int) -> str:
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{' + str(length) + '}', value):
        raise ValueError(f'Expected a {length}-character lowercase digest')
    return value


def snapshot_metadata(data: bytes) -> dict:
    import io
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            text = stream.read(MAX_BYTES + 1).decode('utf-8')
    except zlib.error as exc:
        raise ValueError('Invalid compressed PSL snapshot') from exc
    if len(text.encode()) > MAX_BYTES:
        raise ValueError('Public suffix snapshot exceeds size limit')
    found = re.search(r'^// provenance: (.+)$', text, re.M)
    if found:
        value = json.loads(found.group(1))
        _hex(value['commit'], 40)
        return value
    legacy = re.search(r'^// Public Suffix List, MPL-2.0. Snapshot: ([0-9a-f]{40})$', text, re.M)
    if not legacy:
        raise ValueError('Snapshot provenance missing')
    return {'commit': legacy.group(1)}


def prepare_snapshot(raw: bytes, commit: str, blob_sha: str, *, minimum_rules=(5000, 500)) -> bytes:
    _hex(commit, 40); _hex(blob_sha, 40)
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError('Upstream list exceeds size limit or is empty')
    actual = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if actual != blob_sha:
        raise ValueError('Upstream Git blob SHA mismatch')
    sections = {'ICANN': [], 'PRIVATE': []}
    section = None
    events = []
    for line in raw.decode('utf-8').splitlines():
        line = line.strip()
        marker = re.fullmatch(r'// ===(BEGIN|END) (ICANN|PRIVATE) DOMAINS===', line)
        if marker:
            edge, name = marker.groups()
            events.append((edge, name))
            if edge == 'BEGIN':
                if section is not None:
                    raise ValueError('Nested PSL sections')
                section = name
            else:
                if section != name:
                    raise ValueError('Unbalanced PSL section')
                section = None
        elif line and not line.startswith('//'):
            if section is None:
                raise ValueError('PSL rule outside an identified section')
            rule = line[1:] if line.startswith('!') else line[2:] if line.startswith('*.') else line
            labels = rule.encode('idna').decode('ascii').lower().split('.')
            if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
                raise ValueError('Invalid PSL rule')
            sections[section].append(line)
    if events != [('BEGIN', 'ICANN'), ('END', 'ICANN'), ('BEGIN', 'PRIVATE'), ('END', 'PRIVATE')]:
        raise ValueError('Missing, duplicate or unordered PSL sections')
    for (name, rules), minimum in zip(sections.items(), minimum_rules):
        if len(rules) < minimum or len(rules) > 50000 or len(set(rules)) != len(rules):
            raise ValueError(f'Unexpected {name} rule count or duplicates')
    metadata = {'commit': commit, 'source_blob_sha': blob_sha, 'source_sha256': digest(raw),
                'counts': {k: len(v) for k, v in sections.items()}}
    text = '// Public Suffix List, MPL-2.0. Snapshot: ' + commit + '\n'
    text += '// provenance: ' + json.dumps(metadata, sort_keys=True, separators=(',', ':')) + '\n'
    for name, rules in sections.items():
        text += '// ===BEGIN ' + name + ' DOMAINS===\n' + '\n'.join(sorted(rules)) + '\n// ===END ' + name + ' DOMAINS===\n'
    compressed = bytearray(gzip.compress(text.encode('utf-8'), mtime=0))
    compressed[9] = 255
    return bytes(compressed)


def fetch_snapshot(commit: str) -> bytes:
    _hex(commit, 40)
    tree = fetch(f'https://api.github.com/repos/publicsuffix/list/git/trees/{commit}', max_bytes=MAX_BYTES)
    if tree.status != 200:
        raise ValueError(f'Upstream Git tree HTTP {tree.status}')
    payload = json.loads(tree.body)
    entry = next((x for x in payload.get('tree', []) if x.get('path') == 'public_suffix_list.dat' and x.get('type') == 'blob'), None)
    if entry is None:
        raise ValueError('Upstream PSL blob missing')
    response = fetch(f'https://raw.githubusercontent.com/publicsuffix/list/{commit}/public_suffix_list.dat', max_bytes=MAX_BYTES)
    if response.status != 200:
        raise ValueError(f'Upstream PSL HTTP {response.status}')
    return prepare_snapshot(response.body, commit, entry['sha'])


def check_upstream(root: Path = ROOT) -> dict:
    local = snapshot_metadata(safe_path(root / RELATIVE).read_bytes())
    response = fetch('https://api.github.com/repos/publicsuffix/list/commits/main', max_bytes=MAX_BYTES)
    if response.status != 200:
        raise ValueError(f'Upstream commit HTTP {response.status}')
    commit = _hex(json.loads(response.body)['sha'], 40)
    return {'current_commit': local['commit'], 'upstream_commit': commit, 'update_available': commit != local['commit']}


def _recover(root: Path, cache: Path) -> bool:
    journal = root / '.psl-update.json'
    if not journal.exists():
        return False
    tx = read_json(journal)
    if tx['root'] != str(root) or tx['cache'] != str(cache):
        raise ValueError('Pending update belongs to a different source/cache directory')
    if set(tx.get('files', {})) != {RELATIVE, MANIFEST}:
        raise ValueError('Incomplete update journal')
    for relative, row in tx['files'].items():
        if relative not in (RELATIVE, MANIFEST):
            raise ValueError('Unexpected update target')
        _hex(row['before'], 64); _hex(row['after'], 64)
        data = safe_path(cache / row['after']).read_bytes()
        if digest(data) != row['after'] or digest(safe_path(root / relative).read_bytes()) not in (row['before'], row['after']):
            raise ValueError('Update recovery conflict; preserve files for review')
    for relative, row in tx['files'].items():
        atomic_write_bytes(root / relative, safe_path(cache / row['after']).read_bytes())
    journal.unlink()
    return True


def apply_snapshot(root: Path, cache: Path, data: bytes, expected_current: str) -> dict:
    root, cache = safe_path(root), private_dir(cache)
    if root == cache or root in cache.parents:
        raise ValueError('Keep update backups outside the repository')
    _hex(expected_current, 64)
    metadata = snapshot_metadata(data)
    with locked(root / '.psl-update.lock'):
        _recover(root, cache)
        old = safe_path(root / RELATIVE).read_bytes()
        if digest(old) != expected_current:
            raise ValueError('Current PSL changed; review the update again')
        manifest_bytes = safe_path(root / MANIFEST).read_bytes()
        manifest = json.loads(manifest_bytes)
        if manifest['files'].get(RELATIVE) != expected_current:
            raise ValueError('Existing source manifest does not match the current PSL')
        manifest['files'][RELATIVE] = digest(data)
        next_manifest = (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode()
        tx = {'root': str(root), 'cache': str(cache), 'files': {}}
        for name, before, after in ((RELATIVE, old, data), (MANIFEST, manifest_bytes, next_manifest)):
            for content in (before, after):
                path = cache / digest(content)
                if path.exists() and path.read_bytes() != content:
                    raise ValueError('Backup digest collision/corruption')
                atomic_write_bytes(path, content)
            tx['files'][name] = {'before': digest(before), 'after': digest(after)}
        atomic_write_json(root / '.psl-update.json', tx)
        _recover(root, cache)
    return {'previous_sha256': digest(old), 'sha256': digest(data), **metadata}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('check')
    update = sub.add_parser('update')
    update.add_argument('--commit', required=True)
    update.add_argument('--source-file', type=Path); update.add_argument('--blob-sha')
    update.add_argument('--apply', action='store_true')
    update.add_argument('--cache-dir', type=Path); update.add_argument('--expected-current')
    rollback = sub.add_parser('rollback')
    rollback.add_argument('--to', required=True); rollback.add_argument('--expected-current', required=True)
    rollback.add_argument('--cache-dir', type=Path, required=True)
    recovery = sub.add_parser('recover'); recovery.add_argument('--cache-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    root = safe_path(args.root)
    if args.command == 'check':
        result = check_upstream(root)
    elif args.command == 'recover':
        with locked(root / '.psl-update.lock'):
            result = {'recovered': _recover(root, safe_path(args.cache_dir))}
    elif args.command == 'rollback':
        data = safe_path(args.cache_dir / _hex(args.to, 64)).read_bytes()
        if digest(data) != args.to:
            raise ValueError('Backup digest mismatch')
        result = apply_snapshot(root, args.cache_dir, data, args.expected_current)
    else:
        if args.source_file:
            if not args.blob_sha:
                raise ValueError('--blob-sha required for an offline upstream source')
            path = safe_path(args.source_file)
            if path.stat().st_size > MAX_BYTES:
                raise ValueError('Source file exceeds budget')
            data = prepare_snapshot(path.read_bytes(), args.commit, args.blob_sha)
        else:
            data = fetch_snapshot(args.commit)
        result = {**snapshot_metadata(data), 'sha256': digest(data), 'applied': False}
        if args.apply:
            if not args.cache_dir or not args.expected_current:
                raise ValueError('--apply requires --cache-dir and --expected-current')
            result = {**apply_snapshot(root, args.cache_dir, data, args.expected_current), 'applied': True}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError, TypeError, StopIteration) as exc:
        print(json.dumps({'error': str(exc)}), file=sys.stderr)
        sys.exit(2)
