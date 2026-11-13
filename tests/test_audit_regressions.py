"""Regression coverage for AUD-01 through AUD-15, with synthetic fixtures only."""
import copy
import email
import email.policy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch
import zipfile
import zlib

from common import Fixture, ROOT, br, cm, recon, packets
import check_liveness as lv
import ct_radar as radar
import image_hash as images
import storage
from build_eml import build_approved_eml
from dns_json import dns_answers
from domain_names import registrable_domain
from safe_http import FetchResult


def response(payload, url='https://provider.example/rdap'):
    return FetchResult(url, 200, {}, json.dumps(payload).encode(), '93.184.216.34', ())


def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff)


def png(width, height, kind, pixels, palette=None, transparency=None, filter_byte=0):
    rows = b''.join(bytes([filter_byte]) + pixels[y * width * {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[kind]:(y + 1) * width * {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[kind]] for y in range(height))
    raw = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, kind, 0, 0, 0))
    if palette is not None:
        raw += chunk(b'PLTE', palette)
    if transparency is not None:
        raw += chunk(b'tRNS', transparency)
    return raw + chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b'')


def bmp8(palette, indices, width=9, height=8, top_down=False):
    colors = len(palette)
    stride = (width + 3) // 4 * 4
    rows = [bytes(indices[y * width:(y + 1) * width]) + bytes(stride - width) for y in range(height)]
    if not top_down:
        rows.reverse()
    pixels = b''.join(rows)
    pal = b''.join(bytes([b, g, r, 0]) for r, g, b in palette)
    offset = 54 + len(pal)
    header = b'BM' + struct.pack('<IHHI', offset + len(pixels), 0, 0, offset)
    dib = struct.pack('<IiiHHIIIIII', 40, width, -height if top_down else height, 1, 8, 0, len(pixels), 0, 0, colors, 0)
    return header + dib + pal + pixels


class TestParserRepairs(Fixture):
    def test_empty_and_duplicate_style_attributes(self):
        for html in ('<div style>examplebrand</div>', '<div style="" style>examplebrand</div>', '<p>examplebrand</broken>'):
            with self.subTest(html=html):
                self.assertIn('examplebrand', lv._visible_html_text(html))

    def test_hidden_parent_state_is_cached_and_restored(self):
        self.assertEqual(lv._visible_html_text('<section hidden><i>hidden</i></section><p>visible</p>'), 'visible')

    def test_malformed_declaration_does_not_escape_parser(self):
        try:
            text = lv._visible_html_text('<![bogus]><p>examplebrand</p>')
        except ValueError:
            return
        self.assertIn('examplebrand', text)

    def test_patrol_continues_after_over_budget_target(self):
        second, _ = cm.create_case(self.brand, 'https://other.example/', ['COPYRIGHT_CLONE'])
        def fake_fetch(url, *args):
            body = b'<div>' * 20000 if 'suspect' in url else b'examplebrand'
            return FetchResult(url, 200, {}, body, '93.184.216.34', ())
        with patch.object(lv, 'query_direct_dns', return_value={'A': ['93.184.216.34'], 'dns_query_ok': True}), patch.object(lv, 'fetch', side_effect=fake_fetch):
            result = lv.patrol(self.brand, ['examplebrand'])
        self.assertEqual(result['probed_count'], 2)
        self.assertEqual(result['failed_target_count'], 1)
        self.assertEqual(next(r for r in result['results'] if r['case_id'] == second.name)['verdict'], 'CONTENT_OBSERVED')

    def test_repeated_paypal_prefix_finishes_in_subprocess(self):
        script = "import sys;sys.path.insert(0,sys.argv[1]);import recon_target as r;r.extract_storefront_fingerprints('paypal.com/sdk/js?'*20000)"
        subprocess.run([sys.executable, '-S', '-c', script, str(ROOT / 'scripts')], check=True, timeout=4, capture_output=True)

    def test_deep_html_finishes_in_subprocess(self):
        script = "import sys;sys.path.insert(0,sys.argv[1]);import check_liveness as l\ntry:l._visible_html_text('<div>'*20000)\nexcept ValueError:sys.exit(0)\nsys.exit(1)"
        subprocess.run([sys.executable, '-S', '-c', script, str(ROOT / 'scripts')], check=True, timeout=4, capture_output=True)

    def test_html_character_limit(self):
        with self.assertRaises(ValueError):
            lv._visible_html_text('a' * (512 * 1024 + 1))

    def test_html_event_limit(self):
        with self.assertRaises(ValueError):
            lv._visible_html_text('<br>' * 25001)

    def test_fingerprint_budget_and_paypal_parameters(self):
        html = '<script src="https://www.paypal.com/sdk/js?currency=USD&amp;client-id=CLIENT_1234567890"></script>'
        self.assertEqual(recon.extract_storefront_fingerprints(html)['paypal_client_ids'], ['CLIENT_1234567890'])
        with self.assertRaises(ValueError):
            recon.extract_storefront_fingerprints('x' * 600000)


class TestRadarRepairs(Fixture):
    def test_dns_servfail_is_explicit(self):
        with patch.object(radar, 'fetch', return_value=response({'Status': 2})):
            result = radar.probe_domain_dns_signals('bad.example')
        self.assertEqual(len(result['errors']), 2)
        self.assertFalse(result['live_dns'])

    def test_dns_noerror_and_nxdomain_are_valid_negatives(self):
        for status in (0, 3):
            with self.subTest(status=status):
                self.assertEqual(dns_answers({'Status': status}, 'bad.example', 1), [])

    def test_dns_bad_status_and_truncation_are_errors(self):
        for value in ({}, {'Status': True}, {'Status': 5}, {'Status': 0, 'TC': True}, {'Status': 0, 'Answer': None}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                dns_answers(value, 'bad.example', 1)

    def test_dns_answer_owner_must_match(self):
        value = {'Status': 0, 'Answer': [{'name': 'elsewhere.example', 'type': 1, 'data': '8.8.8.8'}]}
        with self.assertRaises(ValueError):
            dns_answers(value, 'bad.example', 1)

    def test_dns_cname_chain_is_supported(self):
        value = {'Status': 0, 'Answer': [{'name': 'bad.example', 'type': 5, 'data': 'cdn.example.'}, {'name': 'cdn.example', 'type': 1, 'data': '8.8.8.8'}]}
        self.assertEqual(len(dns_answers(value, 'bad.example', 1)), 1)

    def test_dns_question_identity_is_checked(self):
        with self.assertRaises(ValueError):
            dns_answers({'Status': 0, 'Question': [{'name': 'elsewhere.example', 'type': 1}]}, 'bad.example', 1)

    def test_live_a_and_failed_mx_remain_partial(self):
        def fake(url, **kwargs):
            if 'type=MX' in url:
                raise OSError('MX timeout')
            from urllib.parse import urlsplit, parse_qs
            host = parse_qs(urlsplit(url).query)['name'][0]
            return response({'Status': 0, 'Answer': [{'name': host, 'type': 1, 'data': '8.8.8.8'}]})
        with patch.object(radar, '_fetch_crt_json', return_value=[]), patch.object(radar, 'fetch', side_effect=fake):
            result = radar.run_radar_scan(self.brand, self.profile, include_lookalikes=True, lookalike_limit=1)
        self.assertEqual(result['status'], 'PARTIAL')
        self.assertEqual(result['pending_count'], 1)
        self.assertIn('MX', result['errors'][0]['error'])
        self.assertNotIn('last_successful_query_at', storage.read_json(self.brand / 'radar_seen.json'))

    def test_total_dns_failure_does_not_advance_success(self):
        with patch.object(radar, '_fetch_crt_json', side_effect=OSError('CT offline')), patch.object(radar, 'fetch', return_value=response({'Status': 2})):
            result = radar.run_radar_scan(self.brand, self.profile, include_lookalikes=True, lookalike_limit=1)
        self.assertEqual(result['status'], 'FAILED')
        self.assertNotIn('last_successful_query_at', storage.read_json(self.brand / 'radar_seen.json'))

    def test_null_mx_means_no_mail_service(self):
        value = response({'Status': 0, 'Answer': [{'name': 'bad.example', 'type': 15, 'data': '0 .'}]})
        with patch.object(radar, 'fetch', return_value=value):
            self.assertEqual(radar._query_doh_rr('bad.example', 'MX'), [])

    def test_small_budget_covers_sources_and_kinds(self):
        sources = ['examplebrand.com', 'secondbrand.com']
        rows = radar.generate_lookalike_domains(sources, sources, max_variants=20)
        self.assertEqual({r['source_domain'] for r in rows}, set(sources))
        self.assertEqual({r['mutation_kind'] for r in rows}, {'omission', 'transposition', 'repetition', 'hyphenation', 'homoglyph_ascii', 'combosquatting'})

    def test_scan_cursor_rotates_across_runs(self):
        queried = []
        def fake(host):
            queried.append(host)
            return {'live_dns': False, 'errors': [], 'a_records': [], 'mx_records': [], 'successful_types': ['A', 'MX']}
        with patch.object(radar, '_fetch_crt_json', return_value=[]), patch.object(radar, 'probe_domain_dns_signals', side_effect=fake):
            radar.run_radar_scan(self.brand, self.profile, include_lookalikes=True, lookalike_limit=2)
            radar.run_radar_scan(self.brand, self.profile, include_lookalikes=True, lookalike_limit=2)
        self.assertEqual(len(set(queried)), 4)

    def test_capacity_retains_readable_state_and_triage(self):
        rows = [{'name_value': f'examplebrand-{i:06d}.example'} for i in range(3000)]
        with patch.object(radar, '_fetch_crt_json', return_value=rows):
            first = radar.run_radar_scan(self.brand, self.profile)
            self.assertEqual(first['status'], 'PARTIAL')
            self.assertEqual(first['pending_count'], radar.MAX_NEW_PER_SCAN)
            domain = first['pending_domains'][0]
            radar.triage(self.brand, domain, 'REJECTED', 'Reviewer', 'Unrelated')
            second = radar.run_radar_scan(self.brand, self.profile)
        self.assertEqual(second['status'], 'OK')
        self.assertNotIn(domain, second['pending_domains'])
        self.assertLess((self.brand / 'radar_seen.json').stat().st_size, storage.MAX_STATE_BYTES)

    def test_total_capacity_is_reported_without_losing_existing(self):
        with patch.object(radar, 'MAX_RADAR_CANDIDATES', 2), patch.object(radar, '_fetch_crt_json', return_value=[{'name_value': f'examplebrand-{i}.example'} for i in range(5)]):
            for _ in range(2):
                result = radar.run_radar_scan(self.brand, self.profile)
                self.assertEqual(result['status'], 'PARTIAL')
                self.assertEqual(result['pending_count'], 2)
                self.assertEqual(result['errors'][0]['deferred_count'], 3)

    def test_json_oversize_preserves_previous_bytes(self):
        path = self.root / 'state.json'
        storage.atomic_write_json(path, {'old': 'value'})
        before = path.read_bytes()
        with patch.object(storage, 'MAX_STATE_BYTES', 50), self.assertRaises(ValueError):
            storage.atomic_write_json(path, {'huge': 'x' * 80})
        self.assertEqual(path.read_bytes(), before)

    def test_long_triage_text_is_rejected(self):
        with self.assertRaises(ValueError):
            radar.triage(self.brand, 'bad.example', 'REJECTED', 'Reviewer', 'x' * 4001)


class TestDomainAndRDAPRepairs(Fixture):
    def test_country_suffixes_are_not_registrable(self):
        for name in ('co.nz', 'com.sg', 'com.mx', 'co.za'):
            with self.subTest(name=name):
                self.assertEqual(registrable_domain(name), '')
                self.assertEqual(registrable_domain('brand.' + name), 'brand.' + name)

    def test_private_suffixes_are_separate_from_rdap(self):
        self.assertEqual(registrable_domain('shop.brand.github.io'), 'brand.github.io')
        self.assertEqual(recon.domain_rdap_candidates('shop.brand.github.io'), ['shop.brand.github.io', 'brand.github.io', 'github.io'])

    def test_wildcard_and_exception_rules(self):
        self.assertEqual(registrable_domain('a.b.ck'), 'a.b.ck')
        self.assertEqual(registrable_domain('www.ck'), 'www.ck')
        self.assertEqual(registrable_domain('shop.city.kawasaki.jp'), 'city.kawasaki.jp')
        self.assertEqual(registrable_domain('foo.kawasaki.jp'), '')

    def test_idn_psl_rules(self):
        self.assertEqual(registrable_domain('shop.brand.公司.cn'), 'brand.xn--55qx5d.cn')

    def test_unknown_suffix_fails_without_guessing(self):
        self.assertEqual(registrable_domain('brand.invalidsuffix'), '')

    def test_rdap_stops_at_registered_domain(self):
        self.assertEqual(recon.domain_rdap_candidates('shop.examplebrand.co.nz'), ['shop.examplebrand.co.nz', 'examplebrand.co.nz'])
        rows = radar.generate_lookalike_domains(['examplebrand.co.nz'], ['examplebrand.co.nz'], max_variants=20)
        self.assertTrue(all(r['domain'] != 'oc.nz' for r in rows))
        self.assertTrue(any(r['domain'].endswith('.co.nz') for r in rows))

    def test_rdap_rejects_foreign_domain(self):
        boot = response({'services': [[['example'], ['https://rdap.provider.example/']]]})
        wrong = response({'objectClassName': 'domain', 'ldhName': 'other.example', 'status': ['client hold']})
        with patch.object(recon, 'fetch', side_effect=[boot, wrong]):
            result = recon.query_rdap('bad.example')
        self.assertFalse(result['ok'])

    def test_ip_rdap_requires_network_object_and_containment(self):
        boot = {4: {'services': [[['8.0.0.0/8'], ['https://rdap.provider.example/']]]}}
        payloads = [{}, {'notice': 'maintenance'}, {'objectClassName': 'domain'},
                    {'objectClassName': 'ip network', 'startAddress': '9.0.0.0', 'endAddress': '9.255.255.255'},
                    {'objectClassName': 'ip network', 'startAddress': '::', 'endAddress': 'ffff::'}]
        for payload in payloads:
            with self.subTest(payload=payload), patch.object(recon, 'fetch', return_value=response(payload)), patch.object(recon, 'query_ip_asn_doh', return_value={'ok': False}):
                self.assertFalse(recon.query_ip_rdap('8.8.8.8', boot)['rdap_ok'])

    def test_valid_ip_rdap_range(self):
        boot = {4: {'services': [[['8.0.0.0/8'], ['https://rdap.provider.example/']]]}}
        doc = {'objectClassName': 'ip network', 'startAddress': '8.8.8.0', 'endAddress': '8.8.8.255', 'ipVersion': 'v4', 'arin_originas0_originautnums': [15169]}
        with patch.object(recon, 'fetch', return_value=response(doc)):
            self.assertTrue(recon.query_ip_rdap('8.8.8.8', boot)['rdap_ok'])

    def test_valid_ipv6_rdap_range(self):
        boot = {6: {'services': [[['2001:4860::/32'], ['https://rdap.provider.example/']]]}}
        doc = {'objectClassName': 'ip network', 'startAddress': '2001:4860::', 'endAddress': '2001:4860:ffff:ffff:ffff:ffff:ffff:ffff', 'ipVersion': 'v6', 'arin_originas0_originautnums': [15169]}
        with patch.object(recon, 'fetch', return_value=response(doc)):
            self.assertTrue(recon.query_ip_rdap('2001:4860:4860::8888', boot)['rdap_ok'])

    def test_asn_prefix_must_contain_queried_ip(self):
        doc = {'Status': 0, 'Answer': [{'name': '8.8.8.8.origin.asn.cymru.com', 'type': 16, 'data': '15169 | 9.9.9.0/24 | US | arin'}]}
        with patch.object(recon, 'fetch', return_value=response(doc)):
            self.assertFalse(recon.query_ip_asn_doh('8.8.8.8')['ok'])

    def test_rdap_entity_depth_limit(self):
        root = {}; node = root
        for _ in range(30):
            child = {}; node['entities'] = [child]; node = child
        with self.assertRaises(ValueError):
            recon.parse_rdap_domain_json({'entities': [root]})


class TestWorkflowRepairs(Fixture):
    def agent(self):
        p = copy.deepcopy(self.profile)
        p['public_filing_agent'] = {'name': 'Example Agent', 'title': 'Filing Agent', 'legal_email': 'review@agent.example', 'entity_address': 'Synthetic PO Box', 'phone': '+1-202-555-0199'}
        br.register_brand(p['brand_slug'], self.brand, p, self.registry)

    def cli(self, script, *args, expected=0, extra_env=None):
        env = dict(os.environ, BRAND_TAKEDOWN_REGISTRY=str(self.registry))
        env.update(extra_env or {})
        result = subprocess.run([sys.executable, '-S', str(ROOT / 'scripts' / script), *map(str, args)], capture_output=True, text=True, timeout=15, env=env)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return json.loads(result.stdout or result.stderr)

    def test_external_agent_full_cli_workflow(self):
        self.agent(); self.channel()
        source = self.root / 'comparison.txt'; source.write_text('Synthetic image comparison')
        capture = self.cli('recon_target.py', 'add-evidence', '--slug', 'example-brand', '--case-dir', self.case, '--url', 'https://suspect.example/product', '--source', source)
        request = self.request(capture['capture_id']); request['public_archive_expected'] = True
        request['claims'][0]['evidence'][0]['filename'] = source.name
        req = self.root / 'request.json'; req.write_text(json.dumps(request))
        draft = self.cli('packets.py', '--slug', 'example-brand', '--case-dir', self.case, 'prepare', '--request-file', req)
        self.cli('packets.py', '--slug', 'example-brand', '--case-dir', self.case, 'approve', '--packet-id', draft['packet_id'], '--reviewer', 'Reviewer', '--reviewed-digest', draft['packet_sha256'], '--confirm-human-review')
        out = self.cli('build_eml.py', '--slug', 'example-brand', '--case-dir', self.case, '--packet-id', draft['packet_id'])
        mail = email.message_from_bytes(Path(out['eml_path']).read_bytes(), policy=email.policy.default)
        self.assertEqual(str(mail['From']), 'review@agent.example')
        self.assertFalse(out['sent'])

    def test_unconfigured_packet_sender_is_rejected(self):
        self.agent(); self.channel(); cap = self.capture(); req = self.request(cap['capture_id']); req['public_archive_expected'] = True
        draft = packets.prepare_packet(self.case, req)
        path = Path(draft['packet_dir']) / 'packet.json'; data = json.loads(path.read_text()); data['from_addr'] = 'other@agent.example'; path.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'signer'):
            packets.approve_packet(self.case, draft['packet_id'], 'Reviewer', hashlib.sha256(path.read_bytes()).hexdigest(), True)

    def test_agent_profile_change_requires_reapproval(self):
        self.agent(); self.channel(); cap = self.capture(); req = self.request(cap['capture_id']); req['public_archive_expected'] = True
        draft = packets.prepare_packet(self.case, req); packets.approve_packet(self.case, draft['packet_id'], 'Reviewer', draft['packet_sha256'], True)
        p = br.profile_from_dir(self.brand); p['public_filing_agent']['legal_email'] = 'changed@agent.example'
        br.register_brand(p['brand_slug'], self.brand, p, self.registry)
        with self.assertRaises(ValueError):
            build_approved_eml(self.case, draft['packet_id'], Path(draft['packet_dir']) / 'notice.eml')

    def test_hmac_policy_missing_key_blocks_new_capture_before_network(self):
        p = copy.deepcopy(self.profile); p['require_evidence_hmac'] = True
        br.register_brand(p['brand_slug'], self.brand, p, self.registry)
        with patch.dict(os.environ, {'BRAND_TAKEDOWN_HMAC_KEY': ''}), patch.object(recon, 'fetch') as fetch, self.assertRaisesRegex(ValueError, 'HMAC'):
            recon.run_recon('https://suspect.example/product', self.case)
        fetch.assert_not_called()

    def test_hmac_env_policy_blocks_unsigned_legacy_capture(self):
        self.channel(); cap = self.capture()
        with patch.dict(os.environ, {'BRAND_TAKEDOWN_REQUIRE_HMAC': '1', 'BRAND_TAKEDOWN_HMAC_KEY': 'secret'}), self.assertRaisesRegex(ValueError, 'HMAC'):
            packets.prepare_packet(self.case, self.request(cap['capture_id']))

    def test_hmac_brand_policy_blocks_unsigned_legacy_capture(self):
        self.channel(); cap = self.capture()
        p = copy.deepcopy(self.profile); p['require_evidence_hmac'] = True; br.register_brand(p['brand_slug'], self.brand, p, self.registry)
        with patch.dict(os.environ, {'BRAND_TAKEDOWN_HMAC_KEY': 'secret'}), self.assertRaisesRegex(ValueError, 'HMAC'):
            packets.prepare_packet(self.case, self.request(cap['capture_id']))

    def test_hmac_downgrade_blocks_every_later_workflow_stage(self):
        self.channel()
        with patch.dict(os.environ, {'BRAND_TAKEDOWN_HMAC_KEY': 'secret', 'BRAND_TAKEDOWN_REQUIRE_HMAC': '1'}):
            cap = self.capture(); req = self.request(cap['capture_id'])
            draft = packets.prepare_packet(self.case, req)
            packets.approve_packet(self.case, draft['packet_id'], 'Reviewer', draft['packet_sha256'], True)
            directory = self.case / 'evidence' / cap['capture_id']; path = directory / 'evidence-manifest.json'
            manifest = json.loads(path.read_text()); manifest.pop('hmac_algorithm'); manifest.pop('hmac_sha256')
            path.write_text(json.dumps(manifest))
            case = storage.read_json(self.case / 'case.json'); case['captures'][0]['manifest_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest(); storage.atomic_write_json(self.case / 'case.json', case)
            operations = [lambda: packets.prepare_packet(self.case, req),
                          lambda: packets.approve_packet(self.case, draft['packet_id'], 'Reviewer', draft['packet_sha256'], True),
                          lambda: packets.verify_approved_packet(self.case, draft['packet_id']),
                          lambda: build_approved_eml(self.case, draft['packet_id'], Path(draft['packet_dir']) / 'notice.eml'),
                          lambda: cm.confirm_submission(self.case, 'host', draft['packet_id'], 'receipt', br.utc_now())]
            for operation in operations:
                with self.subTest(operation=operation), self.assertRaisesRegex(ValueError, 'HMAC'):
                    operation()

    def test_hmac_valid_full_cli_flow(self):
        env = {'BRAND_TAKEDOWN_REQUIRE_HMAC': '1', 'BRAND_TAKEDOWN_HMAC_KEY': 'cli-secret'}
        source = self.root / 'comparison.txt'; source.write_text('Synthetic comparison'); self.channel()
        cap = self.cli('recon_target.py', 'add-evidence', '--slug', 'example-brand', '--case-dir', self.case, '--url', 'https://suspect.example/product', '--source', source, extra_env=env)
        req = self.request(cap['capture_id']); req['claims'][0]['evidence'][0]['filename'] = source.name
        path = self.root / 'request.json'; path.write_text(json.dumps(req))
        d = self.cli('packets.py', '--slug', 'example-brand', '--case-dir', self.case, 'prepare', '--request-file', path, extra_env=env)
        self.cli('packets.py', '--slug', 'example-brand', '--case-dir', self.case, 'approve', '--packet-id', d['packet_id'], '--reviewer', 'Reviewer', '--reviewed-digest', d['packet_sha256'], '--confirm-human-review', extra_env=env)
        self.cli('build_eml.py', '--slug', 'example-brand', '--case-dir', self.case, '--packet-id', d['packet_id'], extra_env=env)
        result = self.cli('case_manager.py', 'submit', '--slug', 'example-brand', '--case-dir', self.case, '--channel-id', 'host', '--packet-id', d['packet_id'], '--submission-ref', 'synthetic', '--sent-at', br.utc_now(), extra_env=env)
        self.assertEqual(result['channels'][0]['status'], 'SUBMITTED')

    def test_bad_hmac_policy_flag_rejected(self):
        with patch.dict(os.environ, {'BRAND_TAKEDOWN_REQUIRE_HMAC': 'treu'}), self.assertRaises(ValueError):
            recon._hmac_policy()

    def right_request(self, route, kind, territory='US', right_type='design'):
        certificate = self.root / 'certificate.txt'; certificate.write_text('Synthetic certificate')
        p = copy.deepcopy(self.profile)
        p['target_markets'].append('CN_EXPORT')
        if kind == 'DESIGN':
            p['patents_and_designs'] = [{'jurisdiction': territory, 'type': right_type, 'status': 'registered', 'reg_number': 'SYNTHETIC', 'cert_file_path': str(certificate)}]
        else:
            p['trademarks'] = [{'jurisdiction': territory, 'mark_text': 'Example', 'status': 'registered', 'reg_number': 'SYNTHETIC', 'cert_file_path': str(certificate)}]
        br.register_brand(p['brand_slug'], self.brand, p, self.registry)
        self.channel(channel_class='REGULATORY_FILING' if route == 'REGULATORY_FILING' else 'ENFORCEMENT_SLA')
        cap = self.capture(); req = self.request(cap['capture_id']); req['route'] = route; req['claims'][0]['kind'] = kind
        return req

    def test_utility_patent_cannot_support_design_notice(self):
        req = self.right_request('DESIGN_NOTICE', 'DESIGN', right_type='utility')
        with self.assertRaisesRegex(ValueError, 'design right'):
            packets.prepare_packet(self.case, req)

    def test_design_right_remains_usable(self):
        draft = packets.prepare_packet(self.case, self.right_request('DESIGN_NOTICE', 'DESIGN'))
        self.assertTrue(draft['packet_id'])

    def test_cn_export_accepts_cn_trademark(self):
        req = self.right_request('REGULATORY_FILING', 'TRADEMARK', territory='CN'); req['jurisdiction'] = 'CN_EXPORT'
        draft = packets.prepare_packet(self.case, req)
        packets.approve_packet(self.case, draft['packet_id'], 'Reviewer', draft['packet_sha256'], True)
        self.assertTrue(packets.verify_approved_packet(self.case, draft['packet_id']))

    def test_cn_export_rejects_foreign_trademark(self):
        req = self.right_request('REGULATORY_FILING', 'TRADEMARK'); req['jurisdiction'] = 'CN_EXPORT'
        with self.assertRaisesRegex(ValueError, 'territory'):
            packets.prepare_packet(self.case, req)

    def test_cn_export_does_not_enable_nonregulatory_notice(self):
        req = self.right_request('TRADEMARK_NOTICE', 'TRADEMARK', territory='CN'); req['jurisdiction'] = 'CN_EXPORT'
        with self.assertRaises(ValueError):
            packets.prepare_packet(self.case, req)


class TestImageRepairs(Fixture):
    def test_bmp_palette_reordering_preserves_luma_and_hash(self):
        palette = [(x * 28, x * 28, x * 28) for x in range(9)]
        indices = list(range(9)) * 8
        a, b = self.root / 'a.bmp', self.root / 'b.bmp'
        a.write_bytes(bmp8(palette, indices)); b.write_bytes(bmp8(palette[::-1], [8 - i for i in indices]))
        self.assertEqual(images._decode_bmp_luma(a.read_bytes()), images._decode_bmp_luma(b.read_bytes()))
        self.assertEqual(recon.compare_images_dhash(a, b)['hamming_distance'], 0)

    def test_bmp_top_down_matches_bottom_up(self):
        palette = [(0, 0, 0), (255, 255, 255)]; indices = [i % 2 for i in range(72)]
        self.assertEqual(images._decode_bmp_luma(bmp8(palette, indices)), images._decode_bmp_luma(bmp8(palette, indices, top_down=True)))

    def test_bmp_invalid_palette_index_rejected(self):
        with self.assertRaises(ValueError):
            images._decode_bmp_luma(bmp8([(0, 0, 0)], [1] * 72))

    def test_bmp_header_overlap_and_planes_rejected(self):
        raw = bmp8([(0, 0, 0)], [0] * 72)
        for offset, data in ((10, struct.pack('<I', 1)), (26, struct.pack('<H', 0)), (46, struct.pack('<I', 257))):
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                images._decode_bmp_luma(raw[:offset] + data + raw[offset + len(data):])

    def test_rgba_hidden_colors_have_no_effect(self):
        a = png(9, 8, 6, bytes([0, 0, 0, 0]) * 72)
        b = png(9, 8, 6, bytes([200, 70, 180, 0]) * 72)
        self.assertEqual(images._decode_png_luma(a)[2], bytearray([255] * 72))
        self.assertEqual(images._decode_png_luma(a), images._decode_png_luma(b))

    def test_rgba_half_alpha_white_composite(self):
        raw = png(1, 1, 6, bytes([100, 100, 100, 128]))
        self.assertEqual(images._decode_png_luma(raw)[2], bytearray([177]))

    def test_gray_alpha_composite(self):
        raw = png(2, 1, 4, bytes([0, 0, 100, 128]))
        self.assertEqual(list(images._decode_png_luma(raw)[2]), [255, 177])

    def test_indexed_trns_composite(self):
        raw = png(2, 1, 3, bytes([0, 1]), palette=bytes([0, 0, 0, 100, 100, 100]), transparency=bytes([0, 128]))
        self.assertEqual(list(images._decode_png_luma(raw)[2]), [255, 177])

    def test_gray_and_rgb_transparent_keys(self):
        gray = png(2, 1, 0, bytes([30, 70]), transparency=struct.pack('>H', 30))
        rgb = png(2, 1, 2, bytes([30, 30, 30, 70, 70, 70]), transparency=struct.pack('>HHH', 30, 30, 30))
        self.assertEqual(list(images._decode_png_luma(gray)[2]), [255, 70])
        self.assertEqual(images._decode_png_luma(gray), images._decode_png_luma(rgb))

    def test_missing_iend_is_rejected(self):
        with self.assertRaises(ValueError):
            images._decode_png_luma(png(1, 1, 0, b'\x00')[:-12])

    def test_bad_crc_is_rejected(self):
        raw = png(1, 1, 0, b'\x00')
        with self.assertRaisesRegex(ValueError, 'CRC'):
            images._decode_png_luma(raw[:29] + b'\0\0\0\0' + raw[33:])

    def test_png_trailing_data_rejected(self):
        with self.assertRaises(ValueError):
            images._decode_png_luma(png(1, 1, 0, b'\0') + b'junk')

    def test_duplicate_ihdr_rejected(self):
        raw = png(1, 1, 0, b'\0')
        with self.assertRaises(ValueError):
            images._decode_png_luma(raw[:33] + raw[8:33] + raw[33:])

    def test_png_invalid_filter_rejected(self):
        with self.assertRaises(ValueError):
            images._decode_png_luma(png(1, 1, 0, b'\0', filter_byte=5))

    def test_png_compressed_stream_requires_eof_and_exact_size(self):
        raw = png(1, 1, 0, b'\0')
        for stream in (zlib.compress(b'\0\0')[:-2], zlib.compress(b'\0\0\0'), zlib.compress(b'\0\0') + b'trailing'):
            with self.subTest(stream=stream), self.assertRaises(ValueError):
                images._decode_png_luma(raw[:33] + chunk(b'IDAT', stream) + chunk(b'IEND', b''))

    def test_png_palette_and_transparency_lengths_checked(self):
        for raw in (png(1, 1, 3, b'\0'), png(1, 1, 3, b'\0', palette=b'\0'), png(1, 1, 6, b'\0' * 4, transparency=b'\0')):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                images._decode_png_luma(raw)

    def test_png_noncontiguous_idat_rejected(self):
        raw = png(1, 1, 0, b'\0')
        stream = zlib.compress(b'\0\0')
        with self.assertRaises(ValueError):
            images._decode_png_luma(raw[:33] + chunk(b'IDAT', stream[:2]) + chunk(b'tEXt', b'a\0b') + chunk(b'IDAT', stream[2:]) + chunk(b'IEND', b''))

    def test_valid_png_all_five_filters(self):
        pixels = [5, 15, 25, 50, 80, 100]
        for ftype in range(5):
            rows = bytearray(); prev = [0, 0, 0]
            for y in range(2):
                row = pixels[y * 3:y * 3 + 3]; rows.append(ftype)
                for x, v in enumerate(row):
                    a = row[x - 1] if x else 0; b = prev[x]; c = prev[x - 1] if x else 0
                    pred = (0, a, b, (a + b) // 2, images._paeth(a, b, c))[ftype]
                    rows.append((v - pred) & 255)
                prev = row
            raw = png(3, 2, 0, bytes(pixels))
            raw = raw[:33] + chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b'')
            with self.subTest(filter=ftype):
                self.assertEqual(list(images._decode_png_luma(raw)[2]), pixels)
