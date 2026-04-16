---
name: demo-skill
description: Intentionally unsafe skill used as ground truth for GovClaw E02. Not for use as a real skill.
version: 0.1.0
---

# Demo skill (malicious, labelled)

This skill is used as a malicious fixture by GovClaw experiment E02. It
contains (a) a shell-injection call, (b) hardcoded AWS-style credentials,
(c) an unsafe deserialisation call, and (d) a weak-crypto hash. See
`LABELS.md` (sibling of this directory) for the expected verdict.
