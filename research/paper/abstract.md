# Abstract (reusable)

Open agentic-AI runtimes such as OpenClaw expose a new governance surface:
skills, MCP servers, tool calls, and LLM traffic that traditional
software-supply-chain and sandboxing tools cover only partially. We study
**DefenseClaw**, the first public reference implementation of a
*governance layer* for such runtimes — a thin daemon + plugin + CLI that
sits between the agent and its infrastructure and enforces a
scan-before-run admission gate, runtime tool/prompt inspection, and an
auditable allow/block policy store, **without modifying the agent framework
itself**.

We (i) derive a taxonomy of 16 governance challenges specific to open
agentic-AI runtimes, (ii) map each challenge to the DefenseClaw mechanism
that addresses it, (iii) evaluate the mechanisms end-to-end on a labelled
corpus of malicious and benign skills, MCP servers, and agent-generated
code, and (iv) assess the portability of the governance-layer pattern
across multiple claw modes (`openclaw`, `nemoclaw`, `opencode`,
`claudecode`).

Our contributions are: a reusable threat taxonomy, an empirical evaluation
of a production-grade governance layer, a published benchmark corpus with
ground-truth labels, and a portability analysis that sketches a
claw-mode-agnostic governance model. GovClaw's manuscript, experiment
scripts, fixtures, and longitudinal upstream-tracking log are released as
an open-source research package.
