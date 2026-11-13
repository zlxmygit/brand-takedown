"""Continuous workflow regressions for the v1.4.1 follow-up review."""
import copy
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

from common import Fixture, ROOT, br, cm, packets, recon
from build_eml import build_approved_eml
import check_liveness as lv
import ct_radar as ct
import radar_archive as archive
from safe_http import FetchResult
from storage import atomic_write_json, read_json
import update_psl as psl


class WorkflowFixture(Fixture):
    def draft(self, channel_id='host', **fields):
        cap = self.capture()
        request = self.request(cap['capture_id'], channel_id)
        request.update(fields)
        if cm.load_case(self.case)['channels'][0]['channel_class'] == 'REGULATORY_FILING':
            request['route'] = 'REGULATORY_FILING'
        return packets.prepare_packet(self.case, request)

    def approve(self, draft):
        return packets.approve_packet(self.case, draft['packet_id'], 'Reviewer', draft['packet_sha256'], True)

    def send(self, draft, receipt):
        self.approve(draft)
        build_approved_eml(self.case, draft['packet_id'], Path(draft['packet_dir']) / 'notice.eml')
        return cm.confirm_submission(self.case, 'host', draft['packet_id'], receipt, br.utc_now())

    def start(self, regulatory=False):
        self.channel(channel_class='REGULATORY_FILING' if regulatory else 'ENFORCEMENT_SLA')
        self.send(self.draft(), 'initial-receipt')

    def counter(self, ref='counter-1'):
        return cm.record_counter_notice(self.case, 'host', br.utc_now(), 'Review response', source_ref=ref)


class TestCaptureAnalysis(WorkflowFixture):
    def test_large_success_remains_available_to_packets(self):
        self.channel()
        body = b'<html>' + b'a' * (600 * 1024) + b'</html>'
        report = self.capture(body)
        self.assertEqual(report['http_status'], 200)
        self.assertEqual(report['capture_status'], 'CAPTURED')
        self.assertEqual(report['fingerprint_status'], 'ANALYSIS_FAILED')
        self.assertTrue(report['fingerprint_error'])
        self.assertEqual((self.case/'evidence'/report['capture_id']/'raw.bin').read_bytes(), body)
        draft = packets.prepare_packet(self.case, self.request(report['capture_id']))
        self.send(draft, 'large-page-receipt')

    def test_analysis_failure_keeps_http_and_redirect_metadata(self):
        with patch.object(recon, 'extract_storefront_fingerprints', side_effect=ValueError('budget')):
            report = self.capture()
        self.assertEqual(report['capture_status'], 'CAPTURED')
        self.assertTrue(report['peer_ip'])
        self.assertIn('final_url', report)
        self.assertIn('redirect_hops', report)
        self.assertEqual(recon.verify_capture(self.case, report['capture_id'])['target_url'], report['target_url'])

    def test_analysis_failure_does_not_promote_partial_capture(self):
        with patch.object(recon, 'extract_storefront_fingerprints', side_effect=ValueError('budget')):
            report = self.capture(b'')
        self.assertEqual(report['capture_status'], 'PARTIAL')
        self.assertEqual(cm.load_case(self.case)['status'], 'DISCOVERED')

    def test_small_page_still_has_fingerprints(self):
        report = self.capture(b'cdn.shopify.com')
        self.assertEqual(report['fingerprint_status'], 'ANALYZED')
        self.assertEqual(report['fingerprints']['platform_hint'], 'shopify')


class TestSupplements(WorkflowFixture):
    def test_two_supplements_keep_ticket_tier_and_initial_timestamp(self):
        self.start()
        first = cm.load_case(self.case)['channels'][0]['submitted_at']
        for n in range(2):
            cm.update_channel_fields(self.case, 'host', 'NEED_MORE_INFO', ticket_ref='TICKET-SAME')
            draft = self.draft(submission_kind='SUPPLEMENT')
            state = self.send(draft, f'supplement-{n}')
            channel = state['channels'][0]
            self.assertEqual(channel['submitted_at'], first)
            self.assertEqual(channel['escalation_tier'], 1)
            self.assertEqual(channel['history'][-1]['kind'], 'SUPPLEMENT')
            self.assertEqual(channel['history'][-1]['thread_ref'], 'TICKET-SAME')
            self.assertTrue(channel['next_action_due_at'])

    def test_supplement_at_tier_three_stays_tier_three(self):
        self.start()
        cm.mutate_case(self.case, 'fixture', lambda d: d['channels'][0].update(escalation_tier=3, status='ESCALATED_TIER3'))
        cm.update_channel_fields(self.case, 'host', 'NEED_MORE_INFO')
        state = self.send(self.draft(submission_kind='SUPPLEMENT'), 'tier3-supplement')
        self.assertEqual(state['channels'][0]['status'], 'ESCALATED_TIER3')
        self.assertEqual(state['channels'][0]['escalation_tier'], 3)

    def test_regulatory_supplement_has_no_commercial_due(self):
        self.start(regulatory=True)
        cm.update_channel_fields(self.case, 'host', 'NEED_MORE_INFO')
        self.assertEqual(cm.scan_due_escalations(self.brand)[0]['kind'], 'SUPPLEMENT_REVIEW')
        state = self.send(self.draft(submission_kind='SUPPLEMENT'), 'regulatory-supplement')
        self.assertEqual(state['channels'][0]['next_action_due_at'], '')
        self.assertEqual(state['channels'][0]['escalation_tier'], 1)

    def test_duplicate_receipt_on_new_supplement_rejected(self):
        self.start()
        cm.update_channel_fields(self.case, 'host', 'NEED_MORE_INFO')
        draft = self.draft(submission_kind='SUPPLEMENT'); self.approve(draft)
        with self.assertRaises(ValueError):
            cm.confirm_submission(self.case, 'host', draft['packet_id'], 'initial-receipt', br.utc_now())

    def test_supplement_before_provider_request_rejected(self):
        self.start()
        with self.assertRaises(ValueError): self.draft(submission_kind='SUPPLEMENT')

    def test_supplement_wrong_ticket_rejected(self):
        self.start(); cm.update_channel_fields(self.case, 'host', 'NEED_MORE_INFO', ticket_ref='TICKET-1')
        with self.assertRaises(ValueError): self.draft(submission_kind='SUPPLEMENT', thread_ref='WRONG')

    def test_new_supplement_request_invalidates_old_approval(self):
        self.start(); cm.update_channel_fields(self.case, 'host', 'NEED_MORE_INFO')
        draft = self.draft(submission_kind='SUPPLEMENT'); self.approve(draft)
        cm.update_channel_fields(self.case, 'host', 'NEED_MORE_INFO')
        with self.assertRaises(ValueError): packets.verify_approved_packet(self.case, draft['packet_id'])

    def test_supplement_cancels_pending_escalation(self):
        self.start(); cm.advance_escalation_tier(self.case, 'host', '2030-01-01T00:00:00Z')
        cm.update_channel_fields(self.case, 'host', 'NEED_MORE_INFO')
        self.assertNotIn('pending_tier', cm.load_case(self.case)['channels'][0])
        with self.assertRaises(ValueError): cm.advance_escalation_tier(self.case, 'host', '2030-01-01T00:00:00Z')


class TestLegalPause(WorkflowFixture):
    def test_open_task_pauses_due_planning_and_preparation(self):
        self.start(); self.counter()
        due = cm.scan_due_escalations(self.brand, '2030-01-01T00:00:00Z')
        self.assertEqual([x['kind'] for x in due], ['LEGAL_REVIEW'])
        with self.assertRaises(ValueError): cm.advance_escalation_tier(self.case, 'host', '2030-01-01T00:00:00Z')
        with self.assertRaises(ValueError): self.draft()

    def test_existing_draft_and_approval_blocked_after_counter(self):
        self.channel(); draft = self.draft(); self.approve(draft); self.counter()
        with self.assertRaises(ValueError): self.approve(draft)
        with self.assertRaises(ValueError): build_approved_eml(self.case, draft['packet_id'], Path(draft['packet_dir'])/'notice.eml')
        with self.assertRaises(ValueError): cm.confirm_submission(self.case, 'host', draft['packet_id'], 'receipt', br.utc_now())

    def test_other_channel_continues(self):
        self.start(); self.counter(); self.channel('other')
        draft = self.draft(channel_id='other'); self.approve(draft)
        state = cm.confirm_submission(self.case, 'other', draft['packet_id'], 'other-receipt', br.utc_now())
        self.assertEqual(state['status'], 'COUNTER_NOTICE_ALERT')
        self.assertEqual(state['channels'][1]['status'], 'SUBMITTED')

    def test_response_uses_separate_path_and_keeps_pause(self):
        self.start(); state = self.counter(); task_id = state['counter_notices'][0]['task_id']
        draft = self.draft(submission_kind='COUNTER_NOTICE_RESPONSE', legal_task_id=task_id,
                           response_text='Reviewed response text.', response_reviewed_by='Counsel', response_source_ref='counter-1')
        state = self.send(draft, 'legal-response-receipt')
        self.assertEqual(state['counter_notices'][0]['status'], 'OPEN')
        self.assertEqual(state['channels'][0]['next_action_due_at'], '')
        self.assertEqual(state['channels'][0]['escalation_tier'], 1)
        self.assertEqual(state['counter_notices'][0]['responses'][0]['submission_ref'], 'legal-response-receipt')
        body = (Path(draft['packet_dir'])/'notice.txt').read_text(encoding="utf-8")
        self.assertIn('Reviewed response text.', body)
        self.assertNotIn('under penalty of perjury', body)

    def test_response_requires_correct_open_task_and_reviewed_text(self):
        self.start(); self.counter()
        with self.assertRaises(ValueError): self.draft(submission_kind='COUNTER_NOTICE_RESPONSE', legal_task_id='wrong')

    def test_two_tasks_resume_only_after_both_reviewed(self):
        self.start(); self.counter(); state = self.counter('counter-2')
        one, two = state['counter_notices']
        cm.resolve_legal_task(self.case, one['task_id'], 'Counsel', 'Reviewed first')
        self.assertEqual([x['kind'] for x in cm.scan_due_escalations(self.brand, '2030-01-01T00:00:00Z')], ['LEGAL_REVIEW'])
        state = cm.resolve_legal_task(self.case, two['task_id'], 'Counsel', 'Reviewed second')
        self.assertNotIn('legal_pause', state['channels'][0]); self.assertTrue(state['channels'][0]['next_action_due_at'])
        self.assertEqual(cm.scan_due_escalations(self.brand, '2030-01-01T00:00:00Z')[0]['kind'], 'FOLLOWUP_REVIEW')

    def test_resolve_requires_new_packet_not_old_approval(self):
        self.channel(); draft = self.draft(); self.approve(draft)
        state = self.counter(); cm.resolve_legal_task(self.case, state['counter_notices'][0]['task_id'], 'Counsel', 'Reviewed')
        with self.assertRaises(ValueError): packets.verify_approved_packet(self.case, draft['packet_id'])

    def test_resolved_during_pause_does_not_resume_closed_channel(self):
        self.start(); state = self.counter()
        cm.update_channel_fields(self.case, 'host', 'RESOLVED')
        state = cm.resolve_legal_task(self.case, state['counter_notices'][0]['task_id'], 'Counsel', 'Reviewed')
        self.assertEqual(state['channels'][0]['next_action_due_at'], '')


class TestLivenessReview(WorkflowFixture):
    def review(self, decision='DOWN'):
        cap = self.capture()
        refs = [{'capture_id': cap['capture_id'], 'filename': 'raw.bin'}]
        return cm.review_liveness(self.case, decision, 'Reviewer', 'review-source', refs, 'Reviewed all target URLs')

    def probe(self, active):
        with patch.object(lv, 'query_direct_dns', return_value={'A': ['93.184.216.34'], 'AAAA': [], 'dns_query_ok': True}), \
             patch.object(lv, 'fetch', side_effect=(None if active else OSError('timeout')),
                          return_value=FetchResult('https://suspect.example/product', 200, {}, b'examplebrand', '93.184.216.34', ())):
            return lv.probe_case(self.case, ['examplebrand'])

    def test_down_review_survives_unknown_and_latches_returned_content(self):
        self.review(); first = self.probe(False)
        self.assertEqual(first['liveness_state'], 'REVIEWED_DOWN'); self.assertFalse(first['resurrected_alert'])
        second = self.probe(True); self.assertTrue(second['resurrected_alert'])
        self.assertTrue(self.probe(False)['resurrected_alert'])
        self.assertEqual(cm.load_case(self.case)['liveness_review']['decision'], 'DOWN')

    def test_active_review_acknowledges_alert_with_history(self):
        self.review(); self.probe(True); state = self.review('ACTIVE')
        self.assertNotIn('resurrection_alert', state)
        self.assertEqual(len(state['resurrection_alert_history']), 1)
        self.assertEqual(len(state['liveness_reviews']), 2)
        self.assertFalse(self.probe(True)['resurrected_alert'])

    def test_legal_task_is_preserved_during_down_review_and_probe(self):
        self.channel(); self.counter(); self.review(); self.probe(True)
        self.assertEqual(cm.load_case(self.case)['status'], 'COUNTER_NOTICE_ALERT')
        self.assertEqual(cm.scan_due_escalations(self.brand)[0]['kind'], 'LEGAL_REVIEW')

    def test_all_primary_urls_need_review_evidence(self):
        cm.create_case(self.brand, 'https://suspect.example/second', ['COPYRIGHT_CLONE'])
        with self.assertRaises(ValueError): self.review()

    def test_tampered_evidence_rejected(self):
        cap = self.capture(); (self.case/'evidence'/cap['capture_id']/'raw.bin').write_bytes(b'changed')
        with self.assertRaises(ValueError): cm.review_liveness(self.case, 'DOWN', 'Reviewer', 'source', [{'capture_id':cap['capture_id'],'filename':'raw.bin'}], 'reviewed')

    def test_new_target_requires_scope_review(self):
        self.review(); cm.create_case(self.brand, 'https://suspect.example/new', ['COPYRIGHT_CLONE'])
        self.assertEqual(self.probe(False)['liveness_state'], 'SCOPE_CHANGED_REVIEW')

    def test_cli_down_review(self):
        cap = self.capture(); refs = self.root/'refs.json'
        refs.write_text(json.dumps({'evidence':[{'capture_id':cap['capture_id'],'filename':'raw.bin'}]}), encoding="utf-8")
        proc = subprocess.run([sys.executable, str(ROOT/'scripts/case_manager.py'), '--registry', str(self.registry),
                               'review-liveness', '--slug', 'example-brand', '--case-dir', str(self.case), '--decision', 'DOWN',
                               '--reviewer', 'Reviewer', '--source-ref', 'source', '--summary', 'reviewed', '--evidence-file', str(refs)], capture_output=True, text=True, timeout=15, encoding="utf-8")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)['liveness_state'], 'REVIEWED_DOWN')


class TestRadarArchive(Fixture):
    def seed(self, count=10, pending=1):
        data = {'schema_version':2, 'candidates':{}}
        for n in range(count):
            data['candidates'][f'examplebrand-old{n}.example'] = {'status':'REJECTED','first_seen_at':br.utc_now(), 'reviewer':'Reviewer', 'rationale':'Unrelated'}
        for n in range(pending):
            data['candidates'][f'examplebrand-pending{n}.example'] = {'status':'PENDING_REVIEW','first_seen_at':br.utc_now()}
        atomic_write_json(self.brand/'radar_seen.json', data)
        return data

    def scan(self, domains):
        with patch.object(ct, '_fetch_crt_json', return_value=[{'name_value':'\n'.join(domains)}]):
            return ct.run_radar_scan(self.brand, self.profile)

    def test_archive_frees_capacity_and_preserves_pending_and_dedup(self):
        self.seed(10000, 0)
        result = archive.archive_reviewed(self.brand, 'Reviewer', 1000)
        self.assertEqual(result['archived_count'], 1000)
        result2 = self.scan(['examplebrand-old0.example','examplebrand-new.example'])
        self.assertEqual(result2['status'], 'OK')
        self.assertEqual(result2['pending_domains'], ['examplebrand-new.example'])

    def test_pending_never_archived(self):
        self.seed()
        archive.archive_reviewed(self.brand, 'Reviewer')
        self.assertEqual(set(read_json(self.brand/'radar_seen.json')['candidates']), {'examplebrand-pending0.example'})

    def test_export_retains_decisions_and_checksums(self):
        original = self.seed(); result = archive.archive_reviewed(self.brand, 'Reviewer')
        exported = archive.export_batch(self.brand, result['batch_id'])
        self.assertEqual(exported['sha256'], result['sha256'])
        self.assertEqual(exported['entries']['examplebrand-old0.example'], original['candidates']['examplebrand-old0.example'])
        self.assertPrivatePath(self.brand/'radar-archive.sqlite3')

    def test_interrupted_prune_recovers_on_next_scan(self):
        original = self.seed()
        with patch.object(archive, 'atomic_write_json', side_effect=OSError('simulated crash')):
            with self.assertRaises(OSError): archive.archive_reviewed(self.brand, 'Reviewer')
        self.assertEqual(read_json(self.brand/'radar_seen.json'), original)
        result = self.scan(['examplebrand-old0.example','examplebrand-new.example'])
        self.assertEqual(result['recovered_archive_count'], 10)
        self.assertNotIn('examplebrand-old0.example', result['pending_domains'])

    def test_interrupted_prune_does_not_remove_changed_pending_entry(self):
        self.seed()
        with patch.object(archive, 'atomic_write_json', side_effect=OSError('simulated crash')):
            with self.assertRaises(OSError): archive.archive_reviewed(self.brand, 'Reviewer')
        state = read_json(self.brand/'radar_seen.json'); state['candidates']['examplebrand-old0.example']['status'] = 'PENDING_REVIEW'
        atomic_write_json(self.brand/'radar_seen.json', state)
        result = self.scan([])
        self.assertIn('examplebrand-old0.example', result['pending_domains'])

    def test_explicit_restore_keeps_old_audit_record(self):
        self.seed(); batch = archive.archive_reviewed(self.brand, 'Reviewer')
        archive.restore_candidate(self.brand, 'examplebrand-old0.example', 'Reviewer', 'New content observed')
        self.assertIn('examplebrand-old0.example', self.scan([])['pending_domains'])
        self.assertEqual(archive.export_batch(self.brand, batch['batch_id'])['entries']['examplebrand-old0.example']['status'], 'REJECTED')

    def test_rearchive_preserves_both_decisions(self):
        self.seed(); first = archive.archive_reviewed(self.brand, 'Reviewer')
        archive.restore_candidate(self.brand, 'examplebrand-old0.example', 'Reviewer', 'New evidence')
        ct.triage(self.brand, 'examplebrand-old0.example', 'AUTHORIZED', 'Reviewer', 'License verified')
        second = archive.archive_reviewed(self.brand, 'Reviewer')
        self.assertEqual(archive.export_batch(self.brand, first['batch_id'])['entries']['examplebrand-old0.example']['status'], 'REJECTED')
        self.assertEqual(archive.export_batch(self.brand, second['batch_id'])['entries']['examplebrand-old0.example']['status'], 'AUTHORIZED')

    def test_bad_archive_checksum_blocks_prune(self):
        import sqlite3
        self.seed(); archive.archive_reviewed(self.brand, 'Reviewer')
        with closing(sqlite3.connect(self.brand/'radar-archive.sqlite3')) as db, db:
            db.execute("UPDATE entries SET payload='{}'")
        with self.assertRaises(ValueError): self.scan(['examplebrand-old0.example'])

    def test_unreviewed_legacy_rejection_needs_review_before_archive(self):
        state = self.seed(); state['candidates']['examplebrand-old0.example'].pop('reviewer')
        atomic_write_json(self.brand/'radar_seen.json', state)
        with self.assertRaises(ValueError): archive.archive_reviewed(self.brand, 'Reviewer')


class TestPSLUpdates(Fixture):
    def make_snapshot(self, commit='a'*40, tail='tenant.example'):
        raw = ('// ===BEGIN ICANN DOMAINS===\ncom\norg\n// ===END ICANN DOMAINS===\n'
               '// ===BEGIN PRIVATE DOMAINS===\n' + tail + '\n// ===END PRIVATE DOMAINS===\n').encode()
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        return raw, blob, psl.prepare_snapshot(raw, commit, blob, minimum_rules=(2, 1))

    def setup_source(self):
        root = psl.safe_path(self.root/'source'); (root/'references').mkdir(parents=True); (root/'docs').mkdir()
        _,_,data = self.make_snapshot()
        (root/psl.RELATIVE).write_bytes(data)
        atomic_write_json(root/psl.MANIFEST, {'release':'test','files':{psl.RELATIVE:psl.digest(data)}})
        return root, data, psl.safe_path(self.root/'cache')

    def test_pinned_snapshot_has_provenance_and_deterministic_bytes(self):
        raw, blob, data = self.make_snapshot()
        self.assertEqual(data, psl.prepare_snapshot(raw, 'a'*40, blob, minimum_rules=(2, 1)))
        self.assertEqual(psl.snapshot_metadata(data)['source_sha256'], psl.digest(raw))

    def test_wrong_blob_and_malformed_sections_rejected(self):
        raw, blob, _ = self.make_snapshot()
        with self.assertRaises(ValueError): psl.prepare_snapshot(raw, 'a'*40, '0'*40, minimum_rules=(2, 1))
        with self.assertRaises(ValueError): psl.prepare_snapshot(raw, '../main', blob, minimum_rules=(2, 1))
        raw = raw.replace(b'END PRIVATE', b'BEGIN PRIVATE')
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        with self.assertRaises(ValueError): psl.prepare_snapshot(raw, 'a'*40, blob, minimum_rules=(2, 1))

    def test_update_and_rollback_verify_current_and_backup(self):
        root, old, cache = self.setup_source(); _,_,new = self.make_snapshot('b'*40, 'new.example')
        result = psl.apply_snapshot(root, cache, new, psl.digest(old))
        self.assertEqual(result['previous_sha256'], psl.digest(old))
        self.assertEqual(read_json(root/psl.MANIFEST)['files'][psl.RELATIVE], psl.digest(new))
        psl.apply_snapshot(root, cache, (cache/psl.digest(old)).read_bytes(), psl.digest(new))
        self.assertEqual((root/psl.RELATIVE).read_bytes(), old)

    def test_stale_current_rejected_without_change(self):
        root, old, cache = self.setup_source(); _,_,new = self.make_snapshot('b'*40)
        with self.assertRaises(ValueError): psl.apply_snapshot(root, cache, new, '0'*64)
        self.assertEqual((root/psl.RELATIVE).read_bytes(), old)

    def test_interrupted_manifest_write_is_recoverable(self):
        root, old, cache = self.setup_source(); _,_,new = self.make_snapshot('b'*40)
        writer = psl.atomic_write_bytes
        injected = []
        def failing(path, content):
            if psl.safe_path(path) == root/psl.MANIFEST:
                injected.append(path)
                raise OSError('simulated interruption')
            return writer(path, content)
        with patch.object(psl, 'atomic_write_bytes', side_effect=failing):
            with self.assertRaisesRegex(OSError, 'simulated interruption'):
                psl.apply_snapshot(root, cache, new, psl.digest(old))
        self.assertEqual(len(injected), 1)
        self.assertTrue((root/'.psl-update.json').exists())
        self.assertTrue(psl._recover(root, cache))
        self.assertEqual(read_json(root/psl.MANIFEST)['files'][psl.RELATIVE], psl.digest(new))

    def test_backup_corruption_rejected(self):
        root, old, cache = self.setup_source(); _,_,new = self.make_snapshot('b'*40)
        psl.apply_snapshot(root, cache, new, psl.digest(old))
        (cache/psl.digest(old)).write_bytes(b'corrupt')
        with self.assertRaises(ValueError): psl.main(['--root',str(root),'rollback','--to',psl.digest(old),'--cache-dir',str(cache),'--expected-current',psl.digest(new)])


class TestContinuousSequences(WorkflowFixture):
    def make_due(self):
        cm.mutate_case(self.case, 'fixture', lambda d: d['channels'][0].update(next_action_due_at='2000-01-01T00:00:00Z'))

    def test_initial_escalation_supplement_escalation_full_sequence(self):
        self.start(); self.make_due()
        cm.advance_escalation_tier(self.case, 'host', next_sla_hours=24)
        state = self.send(self.draft(), 'second-tier')
        self.assertEqual(state['channels'][0]['escalation_tier'], 2)
        cm.update_channel_fields(self.case, 'host', 'NEED_MORE_INFO', ticket_ref='TICKET')
        state = self.send(self.draft(), 'second-tier-supplement')
        self.assertEqual(state['channels'][0]['escalation_tier'], 2)
        self.assertEqual(state['channels'][0]['followup_hours'], 24)
        self.make_due(); cm.advance_escalation_tier(self.case, 'host')
        state = self.send(self.draft(), 'third-tier')
        self.assertEqual(state['channels'][0]['escalation_tier'], 3)
        self.assertEqual([h['kind'] for h in state['channels'][0]['history'] if h['event']=='transmission_recorded'],
                         ['INITIAL','ESCALATION','SUPPLEMENT','ESCALATION'])

    def test_response_is_available_when_provider_closes_ticket(self):
        self.start(); state = self.counter(); cm.update_channel_fields(self.case, 'host', 'RESOLVED')
        draft = self.draft(submission_kind='COUNTER_NOTICE_RESPONSE', legal_task_id=state['counter_notices'][0]['task_id'],
                           response_text='Reviewed response.', response_reviewed_by='Counsel', response_source_ref='counter-1')
        state = self.send(draft, 'closed-ticket-response')
        self.assertEqual(state['channels'][0]['status'], 'RESOLVED')
        self.assertEqual(state['counter_notices'][0]['status'], 'OPEN')

    def test_response_source_must_match_task(self):
        self.start(); state = self.counter()
        with self.assertRaises(ValueError):
            self.draft(submission_kind='COUNTER_NOTICE_RESPONSE', legal_task_id=state['counter_notices'][0]['task_id'],
                       response_text='Reviewed.', response_reviewed_by='Counsel', response_source_ref='different')

    def test_resolved_task_rejects_prepared_response(self):
        self.start(); state = self.counter(); task_id = state['counter_notices'][0]['task_id']
        draft = self.draft(submission_kind='COUNTER_NOTICE_RESPONSE', legal_task_id=task_id,
                           response_text='Reviewed.', response_reviewed_by='Counsel', response_source_ref='counter-1')
        self.approve(draft)
        cm.resolve_legal_task(self.case, task_id, 'Counsel', 'Reviewed')
        with self.assertRaises(ValueError): packets.verify_approved_packet(self.case, draft['packet_id'])

    def test_legal_pause_freezes_remaining_followup_time(self):
        self.start(); state = self.counter()
        remaining = state['channels'][0]['legal_pause']['remaining_seconds']
        task = state['counter_notices'][0]
        future = '2030-01-01T00:00:00Z'
        with patch.object(cm, 'utc_now', return_value=future):
            state = cm.resolve_legal_task(self.case, task['task_id'], 'Counsel', 'Reviewed')
        delta = cm._parse_iso_utc(state['channels'][0]['next_action_due_at']) - cm._parse_iso_utc(future)
        self.assertAlmostEqual(delta.total_seconds(), remaining, delta=1)

    def test_linked_url_requires_explicit_review_document(self):
        cm.add_linked_cloak_domain(self.case, 'pay.other.example')
        cap = self.capture(); refs = [{'capture_id': cap['capture_id'], 'filename':'raw.bin'}]
        with self.assertRaises(ValueError): cm.review_liveness(self.case,'DOWN','Reviewer','source',refs,'Reviewed')
        file = self.root/'review.txt'; file.write_text('Reviewed primary URL and linked payment page.', encoding="utf-8")
        cap = recon.add_evidence(self.case, 'https://suspect.example/product', file)
        refs = [{'capture_id':cap['capture_id'],'filename':'review.txt','observed_urls':['https://pay.other.example/']}]
        state = cm.review_liveness(self.case,'DOWN','Reviewer','source',refs,'Reviewed')
        self.assertEqual(state['liveness_state'],'REVIEWED_DOWN')

    def test_liveness_review_during_probe_is_not_overwritten(self):
        cap = self.capture(); refs = [{'capture_id':cap['capture_id'],'filename':'raw.bin'}]
        def fetch(url, *args, **kwargs):
            cm.review_liveness(self.case, 'DOWN','Reviewer','source', refs, 'Reviewed after probe began')
            return FetchResult(url,200,{},b'examplebrand','93.184.216.34',())
        with patch.object(lv,'query_direct_dns',return_value={'A':['93.184.216.34'],'dns_query_ok':True}), patch.object(lv,'fetch',side_effect=fetch):
            result = lv.probe_case(self.case,['examplebrand'])
        self.assertFalse(result['resurrected_alert'])
        self.assertEqual(result['liveness_state'],'REVIEWED_DOWN')

    def test_cli_supplement_round_trip(self):
        import os
        self.start(); cm.update_channel_fields(self.case, 'host', 'NEED_MORE_INFO', ticket_ref='CLI-TICKET')
        cap = self.capture(); req = self.request(cap['capture_id']); req['submission_kind'] = 'SUPPLEMENT'
        source = self.root/'request.json'; source.write_text(json.dumps(req), encoding="utf-8")
        env = dict(os.environ, BRAND_TAKEDOWN_REGISTRY=str(self.registry))
        def cli(script, *args):
            result = subprocess.run([sys.executable,str(ROOT/'scripts'/script),*map(str,args)],env=env,capture_output=True,text=True,timeout=15, encoding="utf-8")
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            return json.loads(result.stdout)
        common = ['--slug','example-brand','--case-dir',self.case]
        draft = cli('packets.py', *common, 'prepare','--request-file',source)
        cli('packets.py',*common,'approve','--packet-id',draft['packet_id'],'--reviewer','Reviewer','--reviewed-digest',draft['packet_sha256'],'--confirm-human-review')
        cli('build_eml.py',*common,'--packet-id',draft['packet_id'])
        state = cli('case_manager.py','submit',*common,'--channel-id','host','--packet-id',draft['packet_id'],'--submission-ref','CLI-supplement','--sent-at',br.utc_now())
        self.assertEqual(state['channels'][0]['history'][-1]['kind'],'SUPPLEMENT')

    def test_cli_archive_and_export(self):
        import os
        data={'schema_version':2,'candidates':{'examplebrand-old.example':{'status':'REJECTED','first_seen_at':br.utc_now(),'reviewer':'Reviewer','rationale':'Unrelated'}}}
        atomic_write_json(self.brand/'radar_seen.json',data)
        env = dict(os.environ,BRAND_TAKEDOWN_REGISTRY=str(self.registry))
        cmd=[sys.executable,str(ROOT/'scripts/ct_radar.py'),'--slug','example-brand']
        first=subprocess.run(cmd+['--archive-reviewed','--reviewer','Reviewer'],env=env,capture_output=True,text=True,timeout=15, encoding="utf-8")
        self.assertEqual(first.returncode,0,first.stderr)
        result=json.loads(first.stdout)
        second=subprocess.run(cmd+['--export-batch',result['batch_id']],env=env,capture_output=True,text=True,timeout=15, encoding="utf-8")
        self.assertEqual(second.returncode,0,second.stderr)
        self.assertEqual(json.loads(second.stdout)['count'],1)
