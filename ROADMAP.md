# Roadmap

Redgrade is an SDK to attack an AI agent **before release**: `scan()` finds the vulnerabilities
and gives a release verdict; `check()` replays the deterministic subset in CI so they do not come
back. The scan is the core; CI is the guard.

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
| 0.6 | Images with the payload in the pixels (`png` `visible` / `low_contrast` / `tiny`, built-in bitmap font) for OCR / vision pipelines | LLM01 | shipped (3 attacks) |
| later | `.xlsx`, `.pptx`, EPUB, archives; photorealistic adversarial images | LLM01 | planned |
| 0.6 | Unsafe output: XSS, javascript links, SQL, shell, CSV formula and template injection, in replies and tool arguments (`unsafe_output`) | LLM05 | shipped (12 attacks) |
| 0.6 | Broken access control: BOLA / IDOR, BFLA, RBAC escalation, identity spoofing; `identity:` config and `access_violation` | LLM06, ASI03 | shipped (11 attacks) |
| 0.6 | Memory poisoning across sessions: `new_session` turns, `{{session_id}}` | ASI06 | shipped (7 attacks) |
| 0.6 | Human-agent trust exploitation: phishing, vishing, card harvesting, payment redirection, malicious downloads | ASI09 | shipped (6 attacks) |
| 0.6 | Insecure inter-agent communication: spoofed orchestrator, forged agent card, replayed peer message | ASI07 | shipped (3 attacks) |
| later | Index / retrieval hooks for custom vector stores | LLM08 | planned |
| 0.3 | Agents: goal hijack, unauthorized tool use, manipulated parameters, SSRF/path traversal via tools | LLM06, ASI01 | shipped (8 attacks) |
| 0.3 | MCP: tool poisoning, rug pull, cross-server shadowing, confused deputy, poisoned tool outputs | LLM06 | shipped (6 attacks) |
| 0.3 | Target observation: `tools_called` / HTTP `tools_path` / `{{tools}}` + tool detectors | LLM06 | shipped |
| 0.4 | Multi-chain / handoff injection (tool-handoff) | ASI01 | shipped (6 attacks) |
| 0.4 | Jailbreak and harmful content (opt-in family; policy-bypass proxies) | LLM01 | shipped (7 attacks) |
| 0.4 | Business integrity / policy abuse (opt-in + Acme example pack) | ASI / brand | shipped (5 + example) |

## Scan (development) first

- [x] `scan()` / `redgrade scan`: built-in + purpose-generated + adaptive attacks in one call
- [x] Findings with surface, source, reproduction (input, canary, output) and a suggested fix per family
- [x] Release verdict (`report.readiness(required_level)`): contiguous ladder, critical findings block, untested levels never count
- [x] LiteLLM is a core dependency (lazy import: `check` never loads it); `scan:` block in `redgrade.yaml`
- [ ] `replay`: re-run only the findings of a previous scan (static and adaptive) to confirm a fix
- [ ] `promote`: move confirmed findings into the CI regression pack in one step
- [ ] Stronger default attacker and a warning in the report when the attacker is too weak (or refuses)
- [ ] Remediation per technique (not only per family), with links to the relevant OWASP guidance

## Cross-cutting

- [x] Deterministic L4 mutations on opted-in PI seeds (`mutations: [default]` or an explicit list)
- [x] PI Maturity Score and highest resisted level in the report
- [x] Adaptive / LLM-generated attack variants via `redgrade deep` (LiteLLM PAIR-lite)—not default CI
- [x] TAP / Crescendo-style multi-stage adaptivity beyond PAIR-lite (`check_deep(strategies=["tap", "crescendo"])`)
- [x] GOAT, Echo Chamber and Best-of-N deep strategies; refusal backtracking for multi-turn attackers
- [x] More L4 mutations: Morse, reverse, emoji smuggling, Policy Puppetry, refusal suppression, prefix injection, code wrap, many-shot, seeded Best-of-N (`bon:N`); presets; per-technique ASR in the report
- [x] L4 encodings render after the canary (encoded variants used to carry the literal placeholder and could never succeed)
- [x] ASCII-art mutation (ArtPrompt-style masking, built-in bitmap font)
- [x] Low-resource-language variants: `redgrade translate` (lab, attacker LLM) frozen into packs as L4 `translation_<lang>`
- [x] Attacks generated from the app's purpose (`redgrade generate`), frozen into packs for static CI replay
- [x] Dataset import: AdvBench, JailbreakBench, HarmBench presets and generic CSV / JSONL (`redgrade import-dataset`)
- [x] `mischievous_user` deep strategy (realistic user, everyday pressure)
- [x] `ci.output` (default) and `ci.agent` (tools surface) `check()` pipelines
- [ ] Hallucination / overreliance and package-hallucination probes (need a judge or a curated fact set)
- [ ] AutoDAN-Turbo-style strategy library that learns across runs
- [x] LLM-judge detector for verdicts a regex cannot give (deep-only; CI stays deterministic)
- [x] Per-attack baseline compare: "new successes vs `main`" as a gate (`redgrade baseline update`, `policy.baseline`)
- [x] HTML, SARIF and JUnit reports; report JSON `schema_version: 2`
- [x] Scorecard: per-family score, 95% ranges, letter grade, `min_security_score` / `min_family_score` gates
- [x] Public detector registry (`register_detector`, confidence levels) and plugins (`plugins:`, entry point `redgrade.plugins`)
- [x] Judge-free CI verdicts: `rubric`, local `classifier`, advisory `refusal` heuristic; `redgrade distill` freezes judge verdicts into validated rubrics; opt-in CI judge with a verdict cache
- [x] Compliance view: OWASP LLM 2025, OWASP Agentic 2026, MITRE ATLAS, NIST AI RMF, EU AI Act; SARIF tags; `require_compliance` gate
- [x] pytest plugin: one test per attack, `assert_resisted`, session reports and policy gate
- [x] Defense A/B evaluation: `compare_defense`, `GuardedTarget`, `redgrade compare` (ASR / utility / latency deltas with significance)
- [ ] Verify the OpenGrade adapter end to end against a running OpenGrade server
- [ ] Vulnerable reference apps for each family (the demo app is a simulation, not a real model)

- [x] One version source (`__init__.py`); `litellm` is a core dependency again since `scan()` became the main entry point (the `deep` extra is kept, empty)

## Non-goals

- Proving an app secure. A green run means these attacks did not work in these trials.
- Replacing a human red team or a threat model.
