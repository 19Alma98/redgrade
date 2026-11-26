"""Compliance view: what a run says about each control of the frameworks people report against.

Families (and, optionally, single attacks via ``compliance:`` in a pack) map to controls of:

- ``owasp_llm_2025``  OWASP Top 10 for LLM Applications (2025)
- ``owasp_asi_2026``  OWASP Top 10 for Agentic Applications (2026)
- ``mitre_atlas``     MITRE ATLAS techniques (IDs as published at atlas.mitre.org, 2026)
- ``nist_ai_rmf``     NIST AI RMF 1.0, MEASURE subcategories the tests produce evidence for
- ``eu_ai_act``       EU AI Act articles the tests support (indicative, not legal advice)

Each control gets a status from the run: ``resisted`` (tested, no successful attack),
``vulnerable`` (at least one attack worked), ``not_run`` (redgrade has attacks for it, none ran),
``not_covered`` (no redgrade attack maps to it) or ``out_of_scope`` (inside threats: training
data, model supply chain; use dedicated tools). Advisory verdicts never count.
"""

from collections import defaultdict
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from redgrade.constants import FAMILY_TASK_UTILITY
from redgrade.models import Attack, AttackResult, RunResult
from redgrade.utility import gated_results

__all__ = [
    "FRAMEWORKS",
    "ComplianceReport",
    "ControlStatus",
    "Framework",
    "build_compliance",
    "compliance_markdown",
    "controls_for_attack",
]

Status = Literal["resisted", "vulnerable", "not_run", "not_covered", "out_of_scope"]


class Control(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    in_scope: bool = True


class Framework(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    url: str
    controls: tuple[Control, ...]
    note: str = ""

    @property
    def by_id(self) -> dict[str, Control]:
        return {c.id: c for c in self.controls}


def _c(cid: str, name: str, in_scope: bool = True) -> Control:
    return Control(id=cid, name=name, in_scope=in_scope)


FRAMEWORKS: dict[str, Framework] = {
    f.id: f
    for f in (
        Framework(
            id="owasp_llm_2025",
            name="OWASP Top 10 for LLM Applications 2025",
            url="https://genai.owasp.org/llm-top-10/",
            controls=(
                _c("LLM01", "Prompt Injection"),
                _c("LLM02", "Sensitive Information Disclosure"),
                _c("LLM03", "Supply Chain", in_scope=False),
                _c("LLM04", "Data and Model Poisoning", in_scope=False),
                _c("LLM05", "Improper Output Handling"),
                _c("LLM06", "Excessive Agency"),
                _c("LLM07", "System Prompt Leakage"),
                _c("LLM08", "Vector and Embedding Weaknesses"),
                _c("LLM09", "Misinformation"),
                _c("LLM10", "Unbounded Consumption"),
            ),
        ),
        Framework(
            id="owasp_asi_2026",
            name="OWASP Top 10 for Agentic Applications 2026",
            url="https://genai.owasp.org/",
            controls=(
                _c("ASI01", "Agent Goal Hijack"),
                _c("ASI02", "Tool Misuse and Exploitation"),
                _c("ASI03", "Identity and Privilege Abuse"),
                _c("ASI04", "Agentic Supply Chain Vulnerabilities"),
                _c("ASI05", "Unexpected Code Execution"),
                _c("ASI06", "Memory and Context Poisoning"),
                _c("ASI07", "Insecure Inter-Agent Communication"),
                _c("ASI08", "Cascading Failures"),
                _c("ASI09", "Human-Agent Trust Exploitation"),
                _c("ASI10", "Rogue Agents", in_scope=False),
            ),
        ),
        Framework(
            id="mitre_atlas",
            name="MITRE ATLAS",
            url="https://atlas.mitre.org/",
            note="Technique IDs as published by MITRE; check atlas.mitre.org for the current matrix.",
            controls=(
                _c("AML.T0051.000", "LLM Prompt Injection: Direct"),
                _c("AML.T0051.001", "LLM Prompt Injection: Indirect"),
                _c("AML.T0054", "LLM Jailbreak"),
                _c("AML.T0056", "Extract LLM System Prompt"),
                _c("AML.T0057", "LLM Data Leakage"),
                _c("AML.T0070", "RAG Poisoning"),
                _c("AML.T0077", "LLM Response Rendering"),
                _c("AML.T0080", "AI Agent Context Poisoning"),
                _c("AML.T0029", "Denial of AI Service"),
            ),
        ),
        Framework(
            id="nist_ai_rmf",
            name="NIST AI RMF 1.0 (MEASURE function)",
            url="https://www.nist.gov/itl/ai-risk-management-framework",
            note="Redgrade produces test evidence for these subcategories; it does not implement them.",
            controls=(
                _c("MEASURE 2.5", "System is valid and reliable"),
                _c("MEASURE 2.6", "System is evaluated for safety risks"),
                _c("MEASURE 2.7", "Security and resilience are evaluated"),
                _c("MEASURE 2.10", "Privacy risk is examined"),
            ),
        ),
        Framework(
            id="eu_ai_act",
            name="EU AI Act (Regulation (EU) 2024/1689)",
            url="https://eur-lex.europa.eu/eli/reg/2024/1689/oj",
            note="Indicative mapping of supporting test evidence; not legal advice.",
            controls=(
                _c("Art. 15(1)", "Appropriate level of accuracy (high-risk systems)"),
                _c("Art. 15(4)", "Robustness and resilience to errors and inconsistencies"),
                _c("Art. 15(5)", "Cybersecurity: resilience to adversarial attacks"),
                _c("Art. 55(1)(a)", "GPAI with systemic risk: adversarial testing"),
            ),
        ),
    )
}

_ADV = ("Art. 15(5)", "Art. 55(1)(a)")
_SEC = ("MEASURE 2.7",)

FAMILY_CONTROLS: dict[str, dict[str, tuple[str, ...]]] = {
    "prompt_injection_direct": {
        "owasp_llm_2025": ("LLM01",),
        "mitre_atlas": ("AML.T0051.000",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "prompt_injection_indirect": {
        "owasp_llm_2025": ("LLM01",),
        "owasp_asi_2026": ("ASI01",),
        "mitre_atlas": ("AML.T0051.001",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "file_attachments": {
        "owasp_llm_2025": ("LLM01",),
        "mitre_atlas": ("AML.T0051.001",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "history_injection": {
        "owasp_llm_2025": ("LLM01",),
        "owasp_asi_2026": ("ASI06",),
        "mitre_atlas": ("AML.T0051.000", "AML.T0080"),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "oob_exfiltration": {
        "owasp_llm_2025": ("LLM01", "LLM02"),
        "owasp_asi_2026": ("ASI01", "ASI02"),
        "mitre_atlas": ("AML.T0051.001", "AML.T0057"),
        "nist_ai_rmf": ("MEASURE 2.7", "MEASURE 2.10"),
        "eu_ai_act": _ADV,
    },
    "info_disclosure": {
        "owasp_llm_2025": ("LLM02", "LLM07"),
        "mitre_atlas": ("AML.T0056", "AML.T0057"),
        "nist_ai_rmf": ("MEASURE 2.7", "MEASURE 2.10"),
        "eu_ai_act": _ADV,
    },
    "output_handling": {
        "owasp_llm_2025": ("LLM05",),
        "mitre_atlas": ("AML.T0077",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "output_injection": {
        "owasp_llm_2025": ("LLM05",),
        "owasp_asi_2026": ("ASI05",),
        "mitre_atlas": ("AML.T0077",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "resource_abuse": {
        "owasp_llm_2025": ("LLM10",),
        "mitre_atlas": ("AML.T0029",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": ("Art. 15(4)", "Art. 15(5)"),
    },
    "rag_poisoning": {
        "owasp_llm_2025": ("LLM08",),
        "mitre_atlas": ("AML.T0070", "AML.T0051.001"),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "multi_turn": {
        "owasp_llm_2025": ("LLM01",),
        "mitre_atlas": ("AML.T0051.000", "AML.T0054"),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "task_utility": {
        "nist_ai_rmf": ("MEASURE 2.5",),
        "eu_ai_act": ("Art. 15(1)",),
    },
    "agent_goal_hijack": {
        "owasp_llm_2025": ("LLM06",),
        "owasp_asi_2026": ("ASI01", "ASI02"),
        "mitre_atlas": ("AML.T0051.001",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "mcp_attacks": {
        "owasp_llm_2025": ("LLM06",),
        "owasp_asi_2026": ("ASI02", "ASI04"),
        "mitre_atlas": ("AML.T0051.001",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "agent_handoff": {
        "owasp_asi_2026": ("ASI01", "ASI07", "ASI08"),
        "mitre_atlas": ("AML.T0051.001",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "access_control": {
        "owasp_llm_2025": ("LLM06", "LLM02"),
        "owasp_asi_2026": ("ASI03",),
        "mitre_atlas": ("AML.T0057",),
        "nist_ai_rmf": ("MEASURE 2.7", "MEASURE 2.10"),
        "eu_ai_act": _ADV,
    },
    "memory_poisoning": {
        "owasp_asi_2026": ("ASI06",),
        "mitre_atlas": ("AML.T0080",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "user_manipulation": {
        "owasp_llm_2025": ("LLM09",),
        "owasp_asi_2026": ("ASI09",),
        "nist_ai_rmf": ("MEASURE 2.6",),
        "eu_ai_act": ("Art. 15(4)",),
    },
    "tool_output_injection": {
        "owasp_llm_2025": ("LLM01", "LLM06"),
        "owasp_asi_2026": ("ASI01", "ASI02"),
        "mitre_atlas": ("AML.T0051.001",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "task_aligned_injection": {
        "owasp_llm_2025": ("LLM01", "LLM09"),
        "owasp_asi_2026": ("ASI01",),
        "mitre_atlas": ("AML.T0051.001",),
        "nist_ai_rmf": ("MEASURE 2.5", "MEASURE 2.7"),
        "eu_ai_act": ("Art. 15(1)", "Art. 15(5)"),
    },
    "instruction_file_poisoning": {
        "owasp_llm_2025": ("LLM01",),
        "owasp_asi_2026": ("ASI01", "ASI04"),
        "mitre_atlas": ("AML.T0051.001",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": _ADV,
    },
    "coding_agent": {
        "owasp_llm_2025": ("LLM06", "LLM02"),
        "owasp_asi_2026": ("ASI02", "ASI05"),
        "mitre_atlas": ("AML.T0051.001", "AML.T0057"),
        "nist_ai_rmf": ("MEASURE 2.7", "MEASURE 2.10"),
        "eu_ai_act": _ADV,
    },
    "denial_of_wallet": {
        "owasp_llm_2025": ("LLM10",),
        "owasp_asi_2026": ("ASI08",),
        "mitre_atlas": ("AML.T0029",),
        "nist_ai_rmf": _SEC,
        "eu_ai_act": ("Art. 15(4)", "Art. 15(5)"),
    },
    "jailbreak": {
        "owasp_llm_2025": ("LLM01",),
        "mitre_atlas": ("AML.T0054",),
        "nist_ai_rmf": ("MEASURE 2.6", "MEASURE 2.7"),
        "eu_ai_act": _ADV,
    },
    "business_integrity": {
        "owasp_llm_2025": ("LLM09",),
        "owasp_asi_2026": ("ASI09",),
        "nist_ai_rmf": ("MEASURE 2.6",),
        "eu_ai_act": ("Art. 15(4)",),
    },
}


def controls_for_attack(attack: Attack) -> dict[str, tuple[str, ...]]:
    """Family mapping plus the attack's own ``compliance:`` additions."""
    merged: dict[str, list[str]] = {k: list(v) for k, v in FAMILY_CONTROLS.get(attack.family, {}).items()}
    for fw, ids in attack.compliance.items():
        bucket = merged.setdefault(fw, [])
        bucket.extend(i for i in ids if i not in bucket)
    return {k: tuple(v) for k, v in merged.items()}


class ControlStatus(BaseModel):
    framework: str
    id: str
    name: str
    status: Status
    attacks: int = 0
    valid: int = 0
    successes: int = 0
    asr: float | None = None
    families: list[str] = Field(default_factory=list)
    vulnerable_attacks: list[str] = Field(default_factory=list)


class FrameworkStatus(BaseModel):
    id: str
    name: str
    url: str
    note: str = ""
    controls: list[ControlStatus]

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = defaultdict(int)
        for c in self.controls:
            out[c.status] += 1
        return dict(out)

    @property
    def untested(self) -> list[str]:
        """In-scope controls redgrade can test that this run left untested."""
        return [c.id for c in self.controls if c.status == "not_run"]


class ComplianceReport(BaseModel):
    frameworks: list[FrameworkStatus]

    def framework(self, fw: str) -> FrameworkStatus:
        for f in self.frameworks:
            if f.id == fw:
                return f
        raise KeyError(fw)

    def to_dict(self) -> dict[str, object]:
        return {f.id: f.model_dump() for f in self.frameworks}


def _bad(result: AttackResult) -> int:
    if result.attack.family == FAMILY_TASK_UTILITY:
        return len(result.valid_trials) - result.successes
    return result.successes


def build_compliance(run: RunResult, frameworks: list[str] | None = None) -> ComplianceReport:
    """Per-control status for each framework (all of them by default)."""
    selected = frameworks or list(FRAMEWORKS)
    unknown = [f for f in selected if f not in FRAMEWORKS]
    if unknown:
        raise ValueError(f"unknown frameworks: {', '.join(unknown)} (known: {', '.join(FRAMEWORKS)})")
    executed = [r for r in gated_results(run) if r.valid_trials]
    mapped_families: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for fam, fws in FAMILY_CONTROLS.items():
        for fw_key, ids in fws.items():
            for cid in ids:
                mapped_families[fw_key][cid].add(fam)
    for r in run.results:  # attack-level additions count as coverage too
        for fw_key, ids in r.attack.compliance.items():
            for cid in ids:
                mapped_families[fw_key][cid].add(r.attack.family)

    out: list[FrameworkStatus] = []
    for fw_id in selected:
        fw = FRAMEWORKS[fw_id]
        rows: list[ControlStatus] = []
        for control in fw.controls:
            hits = [r for r in executed if control.id in controls_for_attack(r.attack).get(fw_id, ())]
            valid = sum(len(r.valid_trials) for r in hits)
            bad = sum(_bad(r) for r in hits)
            status: Status
            if hits:
                status = "vulnerable" if bad else "resisted"
            elif not control.in_scope:
                status = "out_of_scope"
            elif mapped_families[fw_id].get(control.id):
                status = "not_run"
            else:
                status = "not_covered"
            rows.append(
                ControlStatus(
                    framework=fw_id,
                    id=control.id,
                    name=control.name,
                    status=status,
                    attacks=len(hits),
                    valid=valid,
                    successes=bad,
                    asr=bad / valid if valid else None,
                    families=sorted(
                        {r.attack.family for r in hits} or mapped_families[fw_id].get(control.id, set())
                    ),
                    vulnerable_attacks=sorted(r.attack.id for r in hits if _bad(r)),
                )
            )
        out.append(FrameworkStatus(id=fw.id, name=fw.name, url=fw.url, note=fw.note, controls=rows))
    return ComplianceReport(frameworks=out)


_LABEL: dict[str, str] = {
    "resisted": "resisted",
    "vulnerable": "**vulnerable**",
    "not_run": "not run",
    "not_covered": "not covered",
    "out_of_scope": "out of scope",
}


def compliance_markdown(report: ComplianceReport, *, heading: str = "##") -> list[str]:
    lines = [
        "",
        f"{heading} Compliance view",
        "",
        "Test evidence per framework control. *resisted* = the mapped attacks did not work in these "
        "trials (not a certification); *not run* = redgrade has attacks for it that this run did not "
        "execute; *not covered* = no redgrade attack maps to it.",
    ]
    for fw in report.frameworks:
        counts = fw.counts()
        summary = ", ".join(f"{n} {_LABEL[s].strip('*')}" for s, n in counts.items())
        lines += ["", f"**{fw.name}** ({summary})", ""]
        if fw.note:
            lines += [f"_{fw.note}_", ""]
        lines += ["| control | status | ASR | evidence |", "|---|---|---|---|"]
        for c in fw.controls:
            asr = "n/a" if c.asr is None else f"{c.asr * 100:.0f}%"
            if c.vulnerable_attacks:
                evidence = "broken by " + ", ".join(c.vulnerable_attacks[:4])
                if len(c.vulnerable_attacks) > 4:
                    evidence += f" (+{len(c.vulnerable_attacks) - 4})"
            elif c.attacks:
                evidence = f"{c.attacks} attack(s): {', '.join(c.families)}"
            else:
                evidence = ", ".join(c.families)
            lines.append(f"| {c.id} {c.name} | {_LABEL[c.status]} | {asr} | {evidence} |")
    return lines
