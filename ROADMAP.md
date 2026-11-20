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
| 0.5 | Real file attachments: PDF / DOCX / HTML / MD / CSV / JSON / PNG-metadata builders, hide techniques, multipart + base64 delivery | LLM01 | shipped (17 attacks) |
| 0.5 | Conversation history injection: forged system / assistant / tool turns, tool trajectories, many-shot priming; `ChatTarget` (OpenAI / Anthropic messages APIs) and `{{messages}}` | LLM01, ASI01 | shipped (9 attacks) |
| 0.5 | Out-of-band collector: attacker web server with per-trial fixtures (pages, JSON APIs, multi-hop chains), `{OOB_URL}`, `oob_callback` detector, inconclusive-when-not-fetched rule; demo browsing agents | LLM01, LLM02, ASI01 | shipped (6 attacks) |
| 0.5 | Five-level ladder for every family (all built-in attacks leveled, L4 mutations beyond PI), contiguous "security level" in Markdown / JSON / HTML / SDK, `min_security_level` / `min_family_level` gates | all | shipped |
| later | DNS / external collectors (interactsh-style) for agents that cannot reach the runner over HTTP | LLM02 | planned |
| later | Visible-text images (OCR / vision injection), `.xlsx`, `.pptx`, EPUB, archives | LLM01 | planned |
| later | More output handling: XSS payloads, SQL and shell injection through model output | LLM05 | planned |
| later | Index / retrieval hooks for custom vector stores | LLM08 | planned |
| 0.3 | Agents: goal hijack, unauthorized tool use, manipulated parameters, SSRF/path traversal via tools | LLM06, ASI01 | shipped (8 attacks) |
| 0.3 | MCP: tool poisoning, rug pull, cross-server shadowing, confused deputy, poisoned tool outputs | LLM06 | shipped (6 attacks) |
| 0.3 | Target observation: `tools_called` / HTTP `tools_path` / `{{tools}}` + tool detectors | LLM06 | shipped |
| 0.4 | Multi-chain / handoff injection (tool-handoff) | ASI01 | shipped (6 attacks) |
| 0.4 | Jailbreak and harmful content (opt-in family; policy-bypass proxies) | LLM01 | shipped (7 attacks) |
| 0.4 | Business integrity / policy abuse (opt-in + Acme example pack) | ASI / brand | shipped (5 + example) |

## Cross-cutting

- [x] Deterministic L4 mutations on opted-in PI seeds (`mutations: [default]` or an explicit list)
- [x] PI Maturity Score and highest resisted level in the report
- [x] Adaptive / LLM-generated attack variants via `redgrade deep` (LiteLLM PAIR-lite)—not default CI
- [x] TAP / Crescendo-style multi-stage adaptivity beyond PAIR-lite (`check_deep(strategies=["tap", "crescendo"])`)
- [x] GOAT, Echo Chamber and Best-of-N deep strategies; refusal backtracking for multi-turn attackers
- [x] More L4 mutations: Morse, reverse, emoji smuggling, Policy Puppetry, refusal suppression, prefix injection, code wrap, many-shot, seeded Best-of-N (`bon:N`); presets; per-technique ASR in the report
- [x] L4 encodings render after the canary (encoded variants used to carry the literal placeholder and could never succeed)
- [ ] Low-resource-language translation and ASCII-art mutations (need offline dictionaries / font tables)
- [x] LLM-judge detector for verdicts a regex cannot give (deep-only; CI stays deterministic)
- [x] Per-attack baseline compare: "new successes vs `main`" as a gate (`redgrade baseline update`, `policy.baseline`)
- [x] HTML, SARIF and JUnit reports; report JSON `schema_version: 2`
- [x] Scorecard: per-family score, 95% ranges, letter grade, `min_security_score` / `min_family_score` gates
- [ ] Verify the OpenGrade adapter end to end against a running OpenGrade server
- [ ] Vulnerable reference apps for each family (the demo app is a simulation, not a real model)

- [x] `litellm` moved to the optional `redgrade[deep]` extra; one version source (`__init__.py`)

## Non-goals

- Proving an app secure. A green run means these attacks did not work in these trials.
- Replacing a human red team or a threat model.
