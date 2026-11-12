import json
import multiprocessing
from pathlib import Path
import threading

from common import Fixture, cm
from storage import ConflictError, atomic_write_json, locked, read_json


def increment(path):
    for _ in range(12):
        with locked(path.with_suffix(".lock")):
            data = read_json(path); data["count"] += 1; atomic_write_json(path, data)


class TestStorage(Fixture):
    def test_stale_revision_rejected(self):
        a = cm.load_case(self.case); b = cm.load_case(self.case)
        a["notes"] = "first"; cm.save_case(self.case, a)
        b["notes"] = "second"
        with self.assertRaises(ConflictError):
            cm.save_case(self.case, b)
        self.assertEqual(cm.load_case(self.case)["notes"], "first")

    def test_multiprocess_transaction(self):
        path = self.root / "counter.json"; atomic_write_json(path, {"count": 0})
        ctx = multiprocessing.get_context("spawn")
        processes = [ctx.Process(target=increment, args=(path,)) for _ in range(4)]
        for process in processes: process.start()
        for process in processes:
            process.join(20); self.assertEqual(process.exitcode, 0)
        self.assertEqual(read_json(path)["count"], 48)

    def test_unique_temporary_names(self):
        path = self.root / "state.json"; errors = []
        def write(n):
            try: atomic_write_json(path, {"n": n})
            except Exception as exc: errors.append(exc)
        threads = [threading.Thread(target=write, args=(n,)) for n in range(12)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(errors, []); self.assertIn("n", read_json(path))
        self.assertEqual(list(self.root.glob(".write-*")), [])

    def test_symlink_state_rejected(self):
        other = self.root / "other.json"; other.write_text('{"x":1}')
        path = self.root / "linked.json"; path.symlink_to(other)
        with self.assertRaises(ValueError): atomic_write_json(path, {"x": 2})
        self.assertEqual(json.loads(other.read_text()), {"x": 1})

    def test_generic_save_cannot_reassign_identity(self):
        data = cm.load_case(self.case); data["brand_id"] = "other"
        with self.assertRaises(ConflictError): cm.save_case(self.case, data)
