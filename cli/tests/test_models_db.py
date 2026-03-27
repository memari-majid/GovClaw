# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.db import Store
from defenseclaw.enforce.policy import PolicyEngine
from defenseclaw.logger import Logger
from defenseclaw.models import ActionState, Finding, ScanResult, compare_severity


class ModelsDbTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.store = Store(self.tmp.name)
        self.store.init()

    def tearDown(self):
        self.store.close()
        os.unlink(self.tmp.name)

    def test_compare_severity(self):
        self.assertGreater(compare_severity("CRITICAL", "HIGH"), 0)
        self.assertGreater(compare_severity("HIGH", "MEDIUM"), 0)
        self.assertLess(compare_severity("LOW", "HIGH"), 0)

    def test_policy_engine_block_allow(self):
        pe = PolicyEngine(self.store)

        self.assertFalse(pe.is_blocked("skill", "bad-skill"))
        pe.block("skill", "bad-skill", "test")
        self.assertTrue(pe.is_blocked("skill", "bad-skill"))

        self.assertFalse(pe.is_allowed("skill", "good-skill"))
        pe.allow("skill", "good-skill", "test")
        self.assertTrue(pe.is_allowed("skill", "good-skill"))

        pe.unblock("skill", "bad-skill")
        self.assertFalse(pe.is_blocked("skill", "bad-skill"))

    def test_policy_engine_quarantine_runtime(self):
        pe = PolicyEngine(self.store)

        pe.quarantine("skill", "s1", "bad")
        self.assertTrue(pe.is_quarantined("skill", "s1"))
        pe.clear_quarantine("skill", "s1")
        self.assertFalse(pe.is_quarantined("skill", "s1"))

        pe.disable("skill", "s1", "runtime")
        action = pe.get_action("skill", "s1")
        self.assertIsNotNone(action)
        self.assertEqual(action.actions.runtime, "disable")

        pe.enable("skill", "s1")
        action = pe.get_action("skill", "s1")
        # Row may still exist with empty state depending on previous fields
        if action is not None:
            self.assertEqual(action.actions.runtime, "")

    def test_logger_writes_scan_and_alerts(self):
        logger = Logger(self.store)
        result = ScanResult(
            scanner="skill-scanner",
            target="/tmp/skill",
            timestamp=datetime.now(timezone.utc),
            findings=[
                Finding(
                    id="f1",
                    severity="HIGH",
                    title="Test finding",
                    description="desc",
                    scanner="skill-scanner",
                )
            ],
            duration=timedelta(milliseconds=1200),
        )

        logger.log_scan(result)

        counts = self.store.get_counts()
        self.assertEqual(counts.total_scans, 1)
        self.assertEqual(counts.alerts, 1)

        alerts = self.store.list_alerts(10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")


if __name__ == "__main__":
    unittest.main()
