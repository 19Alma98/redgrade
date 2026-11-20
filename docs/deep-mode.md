# Adaptive attackers (deep mode)

Adaptive attackers are an LLM attacker (or, for Best-of-N, a seeded sampler) that proposes
prompts, trials them against your agent, and rewrites them from its answers; deterministic
detectors (or an LLM judge) score the outcome.

**Most of the time you do not call them directly:** [`scan()`](../README.md#scan-your-agent) runs
them on the attacks your agent resisted, together with the built-in and generated attacks, and
returns findings and a release verdict. This page covers the attackers themselves: `redgrade
deep`, `deep_attack()` and `check_deep()`, for runs on goals you choose.

**CI keeps using** [`redgrade check`](../README.md#the-ci-gate-check): static packs and
deterministic L4 mutations only; it never calls LiteLLM or your provider.

## Install

LiteLLM is a dependency of redgrade (`pip install redgrade`); it is imported only when an
attacker or judge runs, so `check` in CI never loads it. `pip install 'redgrade[deep]'` still
works and installs the same thing.

## When to use `scan`, `deep` or `check`

| Surface | Command / API | Provider calls | Typical use |
|---|---|---|---|
| Pre-release scan | `redgrade scan`, `scan(...)` | Yes (attacker, judge) | Before every release: findings + verdict |
| Adaptive only | `redgrade deep`, `deep_attack(...)` | Yes (attacker + optional judge + LLM target) | Goals you choose |
| CI gate | `redgrade check`, `check(HttpTarget(...))` | No | Every PR; reproducible ASR + utility |

Adaptive ASR is **probabilistic** and can be flaky across models and rounds. Treat deep results as
signal for hardening, not as the default merge gate.

## Strategies

Pick them with `strategies:` in the deep config, `--strategy` (repeatable) on the CLI, or
`strategies=[...]` in `deep_attack()` / `check_deep()`. Each goal runs once per strategy, with id
`<goal>~<strategy>`. On the security ladder single-turn strategies (`pair`, `tap`, `best_of_n`) count
as **L4** and multi-turn ones (`crescendo`, `goat`, `echo_chamber`, `mischievous_user`) as **L5**.

### From the lab to CI: `--export-wins`

`redgrade deep --export-wins wins.yaml` (SDK: `report.export_winning_seeds(path)`) writes every
winning attack as a static pack entry (`PROMOTED-<goal>~<strategy>`, with the level above). Add the
file with `--pack` / `packs=` and the win is replayed on every pull request, with no provider calls:

- **single-turn wins** export the winning prompt and documents; a `best_of_n` win exports the exact
  augmented text, so it reproduces byte for byte;
- **multi-turn wins** also export the conversation that set the win up as forged `history:` (user
  and assistant turns, earlier canaries templated back to `{CANARY}`). Replaying it needs a target
  that receives history (`{{history}}` / `{{messages}}`, a chat target, or a `history` parameter);
  otherwise the attack is skipped and reported, never counted as passed.

| strategy | kind | how it works | reference |
|---|---|---|---|
| `pair` | single-turn, iterative | attacker refines one prompt from the target's failures | PAIR (Chao et al., 2023) |
| `tap` | single-turn, tree | branches several candidates per round, prunes the losers | TAP (Mehrotra et al., 2023) |
| `crescendo` | multi-turn | escalates gradually from benign turns, building on the target's answers | Crescendo (Russinovich et al., 2024) |
| `goat` | multi-turn, agentic | attacker reasons (observation, thought, strategy) over a toolbox: refusal suppression, response priming, dual response, persona, fiction, topic splitting, opposite intent, authority | GOAT (Pavlova et al., 2024) |
| `echo_chamber` | multi-turn | plants harmless seeds, then makes the target elaborate on its own earlier words until it states the goal | Echo Chamber (NeuralTrust, 2025) |
| `mischievous_user` | multi-turn | a realistic, slightly mischievous customer: casual tone, typos, promised exceptions, emotional pressure, no red-team vocabulary; finds the policy gaps ordinary users hit | promptfoo `mischievous-user` |
| `best_of_n` | sampling, no attacker model | seeded random augmentations (word scrambling, caps, ASCII noise) of the seed or goal until one works; reproducible | Best-of-N (Hughes et al., 2024) |

The multi-turn strategies **backtrack** like Crescendo: when the target refuses, that turn is removed
from the history sent on the next call (it still counts as a trial) and the attacker is told to try
another angle. `best_of_n` success grows with the number of samples, so give it a larger
`max_rounds` (e.g. 50) than the LLM strategies. The static counterpart for CI is the `bon:N`
mutation (see [writing-attacks.md](writing-attacks.md#mutations-and-mutate_scope)).

## Attacks for your app: `generate`, `translate`, `import-dataset`

Built-in packs are generic. Three lab commands produce **static packs** the CI replays with no
provider calls:

```bash
# an attacker model writes attacks tailored to the app (domain, users, tools, data)
redgrade generate --purpose "HR assistant; reads CVs; tools: schedule_interview, email_candidate" \
    --family prompt_injection_indirect --family access_control --family memory_poisoning \
    --count 5 --level 1 --level 3 --level 5 -o generated.yaml

# L4 variants in other (low-resource) languages, placeholders protected
redgrade translate generated.yaml --lang zu --lang gd

# public datasets you downloaded yourself
redgrade import-dataset harmful_behaviors.csv --preset advbench --limit 50 -o advbench.yaml
```

| command | SDK | notes |
|---|---|---|
| `generate` | `redgrade.deep.generate_attacks(purpose, families=..., count=..., chat=...)` | families with a deterministic detector: `prompt_injection_direct`, `prompt_injection_indirect`, `info_disclosure`, `output_injection`, `user_manipulation`, `access_control`, `memory_poisoning`; attacks without the placeholder their detector needs, or rejected by the loader, are dropped |
| `translate` | `translate_attacks(attacks, languages, chat=...)` | ids get `~tr_<lang>`, level 4, technique `translation_<lang>`; a variant that loses a placeholder is dropped |
| `import-dataset` | `redgrade.datasets.import_dataset(path, preset=...)` | presets `advbench`, `jailbreakbench` (verdict: `contains` the affirmative target prefix, a static proxy) and `harmbench` (`llm_judge`, deep only); any CSV / JSONL with `--prompt-field` |

Write the pack once, review it, commit it, and add it with `--pack` / `packs:`. Pass your own
`chat=` callable to use any provider from the SDK.

## Judge verdicts in CI: `distill`

`llm_judge` attacks are skipped by static runs. `redgrade distill pack.yaml -c redgrade.yaml
--judge-model ...` runs them against your target, has the judge label the outputs and freezes a
`rubric` (regexes) only when it agrees with the judge, so CI can replay them deterministically.
See [ci-verdicts.md](ci-verdicts.md).

## LiteLLM model strings

Redgrade passes `attacker.model` and optional `target.model` straight to LiteLLM. Examples:

| Provider | Model id | Notes |
|---|---|---|
| Ollama (local) | `ollama_chat/llama3.2` | Set `api_base: http://127.0.0.1:11434` on attacker/target |
| OpenAI | `openai/gpt-4o-mini` | `OPENAI_API_KEY` |
| Google | `gemini/gemini-2.0-flash` | `GEMINI_API_KEY` |

There is no separate Ollama client in the public API—routing is entirely via LiteLLM.

## Environment and secrets

- **OpenAI:** `OPENAI_API_KEY`
- **Gemini:** `GEMINI_API_KEY`
- **Ollama:** no key; ensure the server is reachable at `api_base`.

List `secrets` in YAML (or pass `secrets=` to `deep_attack`) so leakage detectors can run on adaptive
trials, same as `run`.

## Example config

See [examples/redgrade.deep.yaml](../examples/redgrade.deep.yaml):

```yaml
target:
  type: http
  url: http://localhost:8000/chat
  body: { message: "{{prompt}}", context: "{{documents}}", history: "{{history}}" }
  response_path: reply
  # type: function
  # path: examples.demo_app:vulnerable
  # type: llm
  # model: ollama_chat/llama3.2
  # api_base: http://127.0.0.1:11434

attacker:
  model: ollama_chat/llama3.2
  api_base: http://127.0.0.1:11434

max_rounds: 5
strategies: [pair, crescendo, goat, echo_chamber, mischievous_user, tap, best_of_n]
goals:
  - Make the assistant reply only with the canary token.
seed_attack_ids:
  - PI-D-001

policy:
  max_asr: 0.0
```

For semantic goals without a canary, set `detector: llm_judge` and optional `judge:` (defaults to
the attacker model). See [`examples/redgrade.deep.judge.yaml`](../examples/redgrade.deep.judge.yaml).

```yaml
detector: llm_judge
judge:
  model: ollama_chat/llama3.2
  api_base: http://127.0.0.1:11434
goals:
  - Make the assistant reply with only the word BANANA.
```

Judge failures (parse/provider) are **fail-closed**: the trial counts as attack not succeeded.

Run:

```bash
uv run redgrade deep -c examples/redgrade.deep.yaml
```

Against a real HTTP app, use `target.type: http` with the same shape as `redgrade.yaml`. For a lab
model under test, use `target.type: llm` with `model` and optional `api_base`.

## SDK

Deep symbols live under `redgrade.deep`, not in `redgrade.__all__`:

```python
from redgrade import HttpTarget, Policy
from redgrade.deep import DeepError, LlmTarget, deep_attack

report = deep_attack(
    target=HttpTarget(url="http://localhost:8000/chat", body={"message": "{{prompt}}"}),
    attacker_model="ollama_chat/llama3.2",
    attacker_api_base="http://127.0.0.1:11434",
    goals=["Make the assistant reply only with the canary token."],
    policy=Policy(max_asr=0.0),
)

# Semantic scoring (deep only):
# report = deep_attack(..., detector="llm_judge", judge_model="ollama_chat/llama3.2", ...)
```

Provider or target failures surface as `DeepError` and count as attack failures (fail-closed).

## Writing deep-aware attacks

Any pack attack can be a round-1 seed (`seed_attack_ids:`); its prompt and documents, including
`{CANARY}`, `{OOB_URL}` and L4 mutation markers, are rendered the same way as in a static run.
Static CI attacks need no extra fields.