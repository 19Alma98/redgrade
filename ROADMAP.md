# Roadmap

Redgrade covers attacks that arrive from **outside** the app: user messages, documents, web
pages, tool outputs. Threats from the inside (training-data poisoning, model theft, supply-chain
scanning of dependencies) are out of scope; dedicated tools exist for those.

Families map to the OWASP Top 10 for LLM Applications (2025) and the OWASP Top 10 for Agentic
Applications (2026).

| release | family | OWASP | state |
|---|---|---|---|
| 0.1 | Direct prompt injection (override, fake system, delimiter escape, roleplay, Base64/ROT13, payload splitting, multilingual) | LLM01 | shipped |
| 0.1 | Indirect prompt injection (visible, HTML comment, CV screening, fake end-of-document, encoded) | LLM01 | shipped |
| 0.1 | System prompt, secret and PII leakage | LLM02, LLM07 | shipped |
| 0.1 | Unsafe output handling: markdown/HTML image/link exfiltration | LLM05 | shipped (6 attacks) |
| 0.1 | Unbounded consumption | LLM10 | shipped (5 attacks) |
| 0.2 | RAG and vector poisoning, per-document access control bypass | LLM08 | shipped (5 attacks) |
| 0.2 | Multi-turn attacks (gradual escalation) | LLM01 | shipped (11 attacks) |
| 0.2 | PI maturity: L1–L5 levels, deterministic L4 mutations, PI score in report | LLM01 | shipped |
| 0.2 | Task utility / over-refusal probes + `min_utility` gate | utility | shipped |
| 0.2 | Deep-only `llm_judge` detector | LLM01 | shipped |
| later | More output handling: XSS payloads, SQL and shell injection through model output | LLM05 | planned |
| later | Index / retrieval hooks for custom vector stores | LLM08 | planned |
| 0.3 | Agents: goal hijack, unauthorized tool use, manipulated parameters, SSRF/path traversal via tools | LLM06, ASI01 | shipped (8 attacks) |
| 0.3 | MCP: tool poisoning, rug pull, cross-server shadowing, confused deputy, poisoned tool outputs | LLM06 | shipped (6 attacks) |
| 0.3 | Target observation: `tools_called` / HTTP `tools_path` / `{{tools}}` + tool detectors | LLM06 | shipped |
| 0.4 | Jailbreak and harmful content (optional pack, model-dependent) | LLM01 | planned |

## Cross-cutting

- [x] Deterministic L4 mutations on opted-in PI seeds (`mutations: [default]` or an explicit list)
- [x] PI Maturity Score and highest resisted level in the report
- [x] Adaptive / LLM-generated attack variants via `redgrade deep` (LiteLLM PAIR-lite)—not default CI
- [ ] TAP / Crescendo-style multi-stage adaptivity beyond PAIR-lite
- [x] LLM-judge detector for verdicts a regex cannot give (deep-only; CI stays deterministic)
- [ ] Per-attack baseline compare: "new successes vs `main`" as a gate, like OpenGrade does for quality
- [ ] HTML report
- [ ] Verify the OpenGrade adapter end to end against a running OpenGrade server
- [ ] Vulnerable reference apps for each family (the demo app is a simulation, not a real model)

## Non-goals

- Proving an app secure. A green run means these attacks did not work in these trials.
- Replacing a human red team or a threat model.
