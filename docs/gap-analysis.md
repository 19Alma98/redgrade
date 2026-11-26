# Redgrade: cosa c'è e cosa manca (gap analysis, 2026-11-26)

**Obiettivo del prodotto.** Un SDK Python con cui un AI engineer attacca il proprio agente *prima*
del rilascio, ne misura la robustezza su una scala da attaccante base ad avanzato, corregge e
ripete; poi congela ciò che ha trovato in un gate deterministico per la CI. Il core è la scansione
in sviluppo; la CI è la guardia.

**Riferimenti confrontati:** garak (NVIDIA), promptfoo red team, PyRIT (Microsoft), DeepTeam
(Confident AI, ora `deepeval.red_team`), PIArena (ACL 2026), più la letteratura 2025-2026 sugli
attacchi adattivi agli agenti (AgentDojo/AutoDojo, "The Attacker Moves Second", Skill-Inject).

---

## 1. Verdetto sintetico

La base è già sopra la media degli strumenti open source **per gli attacchi che arrivano da fuori
attraverso l'API di chat**: superfici (prompt, history, documenti, allegati reali, pagine web con
collettore OOB, catalogo tool, memoria tra sessioni, identità), scala L1-L5 con verdetto di
rilascio contiguo, 7 strategie adattive, generazione dal `purpose`, export delle vittorie in pack
deterministici, gate CI senza giudice, mapping OWASP/ATLAS/NIST/EU AI Act. Nessuno degli strumenti
di riferimento ha insieme il verdetto per livello e il ponte "scan → pack congelato → CI".

**Non è ancora "tutto supportato".** I buchi principali non sono nel numero di attacchi, ma in tre
punti che pesano proprio sulla fase di sviluppo:

1. **L'agente deve stare dietro HTTP.** `scan()` rifiuta tutto ciò che non è `HttpTarget` /
   `ChatTarget` (`src/redgrade/scan.py:322`), anche se il motore supporta già i target funzione.
   Un engineer che sviluppa con LangGraph, OpenAI Agents SDK, PydanticAI, CrewAI o semplice
   codice Python deve prima esporre un server. È l'attrito più grande per l'uso come SDK.
2. **I tool dell'agente non vengono mai intercettati.** Gli attacchi via tool arrivano come
   catalogo `{{tools}}` nella richiesta o come turni `tool` falsificati nella history. Negli agenti
   reali l'iniezione indiretta più pericolosa arriva dall'*output di un tool vero* (email letta,
   file aperto, risultato di ricerca, risposta di un server MCP) a metà di un loop agentico. Questo
   è esattamente ciò che misurano AgentDojo, InjecAgent e PIArena, e oggi Redgrade lo copre solo
   per gli agenti che navigano (fixture OOB).
3. **L'attaccante adattivo è debole per default e non viene misurato.** Il default è un modello
   Ollama locale; non c'è un avviso quando l'attaccante rifiuta o non produce varianti valide. La
   letteratura 2025-2026 è concorde: le difese che reggono attacchi statici cadono contro attaccanti
   adattivi forti (es. PIGuard da ~0% a 28% su AutoDojo; 12 difese in-band superate oltre il 90%).
   Un "READY" ottenuto con un attaccante debole è una prova debole, e il report non lo dice.

---

## 2. Confronto per capacità

Legenda: ✅ presente · 🟡 parziale · ❌ assente

| capacità | garak | promptfoo | PyRIT | DeepTeam | PIArena | **Redgrade** |
|---|---|---|---|---|---|---|
| Target HTTP / OpenAI / Anthropic | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ |
| Target Python in-process (callable, async) | ✅ | ✅ | ✅ | ✅ (callback) | ✅ | 🟡 motore sì, `scan()` no |
| Adapter framework agentici (LangGraph, Agents SDK...) | ❌ | 🟡 | 🟡 | 🟡 | 🟡 AgentDojo | ❌ |
| Intercettazione output dei tool reali | ❌ | 🟡 | ❌ | ❌ | ✅ (AgentDojo/InjecAgent) | ❌ (solo fixture OOB) |
| Allegati reali (PDF, DOCX, immagini) | 🟡 | 🟡 | ✅ convertitori | ❌ | ❌ | ✅ |
| Audio / video | 🟡 | ✅ | ✅ | ❌ | ❌ | ❌ |
| History falsificata nativa | ❌ | 🟡 | ✅ | 🟡 | ❌ | ✅ |
| Memoria tra sessioni | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |
| Esfiltrazione out-of-band (collettore) | ❌ | 🟡 | ❌ | ❌ | ❌ | ✅ |
| BOLA / BFLA / RBAC tramite agente | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| Contenuti dannosi (tassonomia ampia: bias, tossicità, ...) | ✅ | ✅ | ✅ | ✅ 50+ | ❌ | 🟡 opt-in, 7 attacchi |
| Allucinazioni / package hallucination / misinformation | ✅ | ✅ | 🟡 | ✅ | ❌ | ❌ |
| Mutazioni/encoding (base64, homoglyph, ...) | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ |
| Composizione di mutazioni (layer/composite) | ❌ | ✅ | ✅ (catena convertitori) | ❌ | ✅ combined | ❌ |
| PAIR / TAP / Crescendo | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Agente attaccante con memoria/tassonomia (meta, Hydra) | ❌ | ✅ | 🟡 | ❌ | ✅ strategy_search | ❌ |
| Bad Likert Judge, math prompt, poesia avversaria | ❌ | ✅ | 🟡 | ✅ | ❌ | ❌ |
| Libreria di strategie che apprende tra run (AutoDAN-Turbo) | ❌ | ❌ | ❌ | ❌ | 🟡 PISmith RL | ❌ (roadmap) |
| GCG / white-box | ✅ | ❌ | 🟡 | ❌ | ✅ nanogcg | ❌ (fuori ambito: serve accesso ai pesi) |
| Livelli di attaccante + verdetto di rilascio | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Utilità sotto attacco (task svolto e attacco fallito) | ❌ | ❌ | ❌ | ❌ | ✅ | 🟡 utilità separata |
| Valutazione difese A/B | ❌ | ❌ | ❌ | 🟡 guardrail | ✅ 9 difese | ✅ |
| Scan → pack deterministico per CI | ❌ | 🟡 | ❌ | ❌ | ❌ | ✅ |

---

## 3. Cosa manca, in ordine di priorità

### P0: la fase di sviluppo con l'SDK

**3.1 `scan()` su qualunque agente Python.**
- Accettare in `scan()` un callable (sync **e** `async def`) oltre a `HttpTarget`. Il motore lo
  supporta già (`wrap_function`); va rimossa la restrizione e documentata la firma
  `(prompt, *, history, documents, attachments, tools, session_id) -> str | TargetObservation`.
- Esecuzione asincrona nativa (asyncio) con limite di concorrenza e rate limit/retry con backoff
  sui 429: oggi c'è un `ThreadPoolExecutor` e nessun retry.
- Risposte in streaming (SSE) per `ChatTarget`.

**3.2 Adapter per i framework agentici** (`redgrade.adapters.*`, extra opzionali):
LangGraph/LangChain, OpenAI Agents SDK, PydanticAI, CrewAI, LlamaIndex, Anthropic tool-use loop,
server MCP. Ogni adapter:
- costruisce il target dall'oggetto agente (`scan(from_langgraph(graph))`);
- **osserva i tool chiamati** tramite callback/tracing del framework (o OpenTelemetry GenAI), così
  i detector `tool_called` / `forbidden_tool` / `access_violation` funzionano senza configurare
  `tools_path`.

**3.3 Interposizione sui tool (il buco più grande per gli agenti).**
Un `ToolInterceptor` che avvolge i tool reali dell'agente e, per un attacco, sostituisce o
avvelena il valore restituito (email, file, record DB, risultato di ricerca, risposta MCP) con il
payload, mentre l'agente lavora a un compito utente legittimo. Il formato di un attacco ha già
quasi tutto ciò che serve (`fixtures`, `{CANARY}`, `requires_tools`); manca un campo del tipo:

```yaml
tool_outputs:
  - tool: read_email          # quando l'agente chiama questo tool...
    match: { folder: inbox }  # ...con questi argomenti (opzionale)
    inject: "...payload con {CANARY}..."
    position: append          # replace | append | prepend
```

Con questo Redgrade può importare e rigiocare AgentDojo, InjecAgent e AgentDyn come pack (vedi
3.9) e misurare l'**utilità sotto attacco**: il task utente è stato completato *e* l'attacco è
fallito? È la metrica che rende credibile un verdetto su un agente.

**3.4 Forza dell'attaccante misurata nel report** (già in roadmap, da alzare a P0).
- Rilevare quando l'attaccante rifiuta o genera varianti invalide, e declassare il verdetto
  ("READY con attaccante debole").
- Calibrazione: prima della scansione, l'attaccante deve rompere un target di riferimento
  volutamente vulnerabile (c'è già la demo app); se non ci riesce, il report lo segnala.
- Default consigliato: un modello frontier via LiteLLM, il modello locale solo come fallback
  esplicito.

**3.5 `replay` e `promote`** (in roadmap): rigiocare solo i finding di una scansione dopo una
correzione, e spostarli nel pack di regressione della CI con un comando. Chiudono il ciclo
"scan → fix → scan" che è il cuore dell'esperienza di sviluppo.

### P1: copertura degli attacchi

**3.6 Strategie adattive mancanti**
- **Meta-agente / Hydra**: attaccante agentico che costruisce una tassonomia di approcci, tiene
  memoria strutturata dei tentativi e cambia ramo quando uno fallisce (promptfoo `jailbreak:meta`,
  `jailbreak:hydra`; PIArena `strategy_search`).
- **Bad Likert Judge** (multi-turn, DeepTeam/promptfoo), **math prompt**, **poesia avversaria**,
  **context flooding**, **synthetic context injection**, **embedded JSON instruction**,
  **emotional manipulation** (catalogo DeepTeam).
- **Libreria di strategie che apprende tra run** (AutoDAN-Turbo, già in roadmap): salvare le
  strategie vincenti per agente e riusarle alla scansione successiva.
- Attacco adattivo **specifico per l'iniezione indiretta**: oggi le strategie riscrivono il prompt;
  per L3 devono riscrivere il *documento / output del tool* (AutoDojo, "The Attacker Moves Second").

**3.7 Composizione di mutazioni.** Catene come `policy_puppetry → base64 → translation_zu`
(promptfoo `layer` / `composite`, catene di convertitori PyRIT, `combined` di PIArena), e
mutazioni applicate anche alle varianti prodotte dalle strategie adattive.

**3.8 Famiglie nuove o da ampliare**
| famiglia | perché | riferimento |
|---|---|---|
| Iniezione allineata al task / disinformazione | PIArena mostra che quando il compito iniettato coincide col compito dell'utente molte difese non funzionano e il canary non lo vede: serve un detector sul risultato (risposta alterata, non token esterno) | PIArena |
| Skill / file di istruzioni avvelenati (`SKILL.md`, `AGENTS.md`, `.cursorrules`, README del repo) | vettore principale per gli agenti di coding nel 2026 | Skill-Inject, promptfoo coding-agent |
| Agenti di coding: output del terminale, test che "verificano" sabotati, letture di `.env`, uscita dalla sandbox | | promptfoo coding-agent |
| Esecuzione di codice inattesa / sandbox escape per agenti con code interpreter | | DeepTeam "Unexpected Code Execution" |
| Autonomia eccessiva, deriva, hijack ricorsivo, furto dell'obiettivo, ricognizione di sistema, debug access | coprono ASI02/ASI10 oltre ad ASI01 | DeepTeam (agentic) |
| Denial of wallet: loop di tool, ricorsione, amplificazione di token | `resource_abuse` ha 5 attacchi, nessuno sui loop agentici | SkillBloat |
| Allucinazioni, package hallucination, overreliance | in roadmap; serve un set di fatti curato o un giudice | garak, DeepTeam |
| Contenuti dannosi con tassonomia completa (bias, tossicità, minori, armi, autolesionismo...) | oggi 7 attacchi opt-in; utile per app consumer, con giudice e rubriche distillate | DeepTeam, promptfoo, garak |
| Agenti computer-use / browser: iniezione nell'interfaccia (testo nella pagina, DOM nascosto, screenshot) | estende `oob_exfiltration` | |
| A2A: agent card avvelenate, impersonificazione tra agenti | 3 attacchi in `agent_handoff`, da ampliare | OWASP ASI07 |

**3.9 Dataset di benchmark come pack.** Oltre ad AdvBench/JailbreakBench/HarmBench: AgentDojo,
InjecAgent, AgentDyn, PIArena (HF `sleeepeer/PIArena`), BIPIA, latentinjection di garak. Dipendono
da 3.3 per le parti agentiche.

### P2: superfici e report

- **Allegati**: `.xlsx`, `.pptx`, EPUB, archivi (in roadmap), QR code nelle immagini, **audio**
  (testo sintetizzato con istruzioni) per agenti vocali, immagini avversarie.
- **Punteggio di rischio per finding** combinando severità, livello e tasso di successo
  (es. allineato a OWASP AIVSS), oltre al verdetto binario.
- **Budget e costi**: token/costo dell'attaccante e del target per fase, limiti `max_cost`,
  ripresa di una scansione interrotta (checkpoint).
- **Report di copertura delle superfici**: quali superfici l'agente espone e quante ne sono state
  attaccate davvero, accanto alle note sugli attacchi saltati.

---

## 4. Cosa non fare

- **GCG e attacchi white-box**: richiedono i pesi del modello; il punto di contatto di Redgrade è
  l'API dell'agente. Fuori ambito, o al massimo come generatore offline di suffissi trasferibili da
  importare come pack.
- **Inseguire il numero di plugin.** promptfoo e DeepTeam contano 50-150 voci, molte sono varianti
  di contenuto dannoso. Il valore di Redgrade è la profondità sugli agenti (superfici, tool,
  livelli, verdetto), non la lunghezza del catalogo.
- **Spostare la scansione in CI.** La CI resta deterministica; gli attacchi adattivi restano in
  sviluppo, e quello che trovano entra in CI solo come pack congelato.

## 5. Sequenza proposta

1. `scan()` su callable sync/async + retry/rate limit (piccolo, sblocca l'uso come SDK).
2. `ToolInterceptor` + adapter LangGraph e OpenAI Agents SDK con osservazione dei tool.
3. Metrica utilità sotto attacco; import AgentDojo/InjecAgent come pack.
4. Forza dell'attaccante nel report + `replay` / `promote`.
5. Strategie meta/Hydra e riscrittura adattiva dei documenti/output dei tool; composizione di mutazioni.
6. Nuove famiglie (iniezione allineata al task, skill poisoning, coding agent, denial of wallet).
7. Allegati e modalità aggiuntive, punteggio di rischio, budget.

## Fonti

- PIArena: <https://arxiv.org/abs/2604.08499>, <https://github.com/sleeepeer/PIArena>
- DeepTeam: <https://github.com/confident-ai/deepteam>
- promptfoo strategies: <https://promptfoo.dev/docs/red-team/strategies/>, agenti: <https://www.promptfoo.dev/docs/red-team/agents>
- PyRIT: <https://microsoft.github.io/PyRIT/latest/code/framework>
- garak: <https://github.com/NVIDIA/garak>, <https://reference.garak.ai/en/latest/probes/latentinjection.html>
- AutoDojo: <https://arxiv.org/pdf/2606.15057>
- The Attacker Moves Second: <https://arxiv.org/pdf/2510.09023>
- Adaptive Attacks Break Defenses Against IPI: <https://arxiv.org/pdf/2503.00061>
- Skill-Inject: <https://arxiv.org/abs/2602.20156>
- SkillBloat: <https://arxiv.org/pdf/2608.21929>
