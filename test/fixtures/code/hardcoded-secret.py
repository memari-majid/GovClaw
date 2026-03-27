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

"""
TEST FIXTURE — intentionally contains a hardcoded secret.
DO NOT use as a template. This file exists to test CodeGuard detection.
"""
import requests

# INTENTIONAL: hardcoded credential for scanner testing
_TEST_API_KEY = "sk-test-1234567890abcdef1234567890abcdef"  # noqa: S105


def call_api() -> dict:
    headers = {"Authorization": f"Bearer {_TEST_API_KEY}"}
    response = requests.get("https://api.example.com/data", headers=headers, timeout=10)
    return response.json()
