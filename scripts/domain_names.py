"""Registrable-domain boundaries from the bundled ICANN and PRIVATE PSL rules."""
from functools import lru_cache
import gzip
from pathlib import Path
from brand_registry import normalize_hostname

PSL_PATH = Path(__file__).resolve().parent.parent / 'references/public_suffix_list.dat.gz'


def _rules(include_private: bool):
    stat = PSL_PATH.stat()
    return _cached_rules(include_private, str(PSL_PATH), stat.st_ino, stat.st_size, stat.st_mtime_ns)


@lru_cache(maxsize=4)
def _cached_rules(include_private: bool, path: str, inode: int, size: int, modified_ns: int):
    with gzip.open(path, 'rt', encoding='utf-8') as stream:
        text = stream.read(2 * 1024 * 1024 + 1)
    if len(text) > 2 * 1024 * 1024:
        raise ValueError('Public suffix snapshot exceeds size limit')
    exact, wildcard, exceptions = set(), set(), set()
    private = False
    for line in text.splitlines():
        line = line.strip()
        if line == '// ===BEGIN PRIVATE DOMAINS===':
            private = True
        if not line or line.startswith('//') or (private and not include_private):
            continue
        bucket = exceptions if line.startswith('!') else wildcard if line.startswith('*.') else exact
        raw = line[1:] if line.startswith('!') else line[2:] if line.startswith('*.') else line
        bucket.add(raw.encode('idna').decode('ascii').lower())
    # Reserved synthetic domain used by offline tests and examples.
    exact.add('example')
    return frozenset(exact), frozenset(wildcard), frozenset(exceptions)


def registrable_domain(host: str, *, include_private: bool = True) -> str:
    clean = normalize_hostname(host)
    if not clean:
        return ''
    labels = clean.split('.')
    exact, wildcard, exceptions = _rules(include_private)
    suffix_size = 0
    for i in range(len(labels)):
        suffix = '.'.join(labels[i:])
        count = len(labels) - i
        if suffix in exceptions:
            suffix_size = count - 1
            break
        if suffix in exact:
            suffix_size = max(suffix_size, count)
        if i and suffix in wildcard:
            suffix_size = max(suffix_size, count + 1)
    # An unknown suffix is not guessed to be a single-label suffix.
    if not suffix_size or len(labels) <= suffix_size:
        return ''
    return '.'.join(labels[-suffix_size - 1:])


def domain_candidates(host: str) -> list[str]:
    clean = normalize_hostname(host)
    # RDAP describes the ICANN registration, not a tenant under a PRIVATE suffix.
    registered = registrable_domain(clean, include_private=False)
    if not registered:
        return []
    labels = clean.split('.')
    return ['.'.join(labels[i:]) for i in range(len(labels) - len(registered.split('.')) + 1)]
