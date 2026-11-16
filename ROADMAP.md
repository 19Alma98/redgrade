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
| 0.1 | Unsafe output handling: markdown image/link exfiltration | LLM05 | shipped (2 attacks) |
| 0.1 | Unbounded consumption | LLM10 | shipped (2 attacks) |
| 0.2 | RAG and vector poisoning, per-document access control bypass | LLM08 | planned |
| 0.2 | More output handling: HTML/XSS, SQL and shell injection through model output | LLM05 | planned |
| 0.2 | Multi-turn attacks (gradual escalation) | LLM01 | planned |
| 0.3 | Agents: goal hijack, unauthorized tool use, manipulated parameters, SSRF/path traversal via tools, memory poisoning | LLM06, ASI01 | planned |
| 0.3 | MCP: tool poisoning, rug pull, cross-server shadowing, confused deputy, poisoned tool outputs | LLM06 | planned |
| 0.4 | Jailbreak and harmful content (optional pack, model-dependent) | LLM01 | planned |

## Cross-cutting

- [ ] LLM-judge detector for verdicts a regex cannot give (policy violations, tone)
- [ ] LLM-generated variants of each attack (mutation), with a fixed seed so runs stay comparable
- [ ] Per-attack baseline compare: "new successes vs `main`" as a gate, like OpenGrade does for quality
- [ ] HTML report
- [ ] Verify the OpenGrade adapter end to end against a running OpenGrade server
- [ ] Vulnerable reference apps for each family (the demo app is a simulation, not a real model)

## Non-goals

- Proving an app secure. A green run means these attacks did not work in these trials.
- Replacing a human red team or a threat model.
