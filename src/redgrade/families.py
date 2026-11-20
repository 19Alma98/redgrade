"""Attack families and their mapping to OWASP Top 10 for LLM Applications (2025) and the
OWASP Top 10 for Agentic Applications (2026).

``status`` says whether the repository ships attacks for the family. Families marked
``planned`` appear in the report's coverage matrix so a green run is never read as
"everything was tested".
"""

from pydantic import BaseModel, ConfigDict

from redgrade.constants import FAMILY_STATUS_AVAILABLE, FamilyStatus


class Family(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    owasp: str
    status: FamilyStatus
    target_release: str
    # Opt-in families ship as builtins but are excluded from default ``run`` /
    # ``load_attacks()`` unless the caller selects them via ``families``.
    opt_in: bool = False


FAMILIES: tuple[Family, ...] = (
    Family(
        id="prompt_injection_direct",
        name="Direct prompt injection",
        owasp="LLM01",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.1",
    ),
    Family(
        id="prompt_injection_indirect",
        name="Indirect prompt injection",
        owasp="LLM01",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.1",
    ),
    Family(
        id="file_attachments",
        name="Malicious file attachments (PDF, DOCX, HTML, images)",
        owasp="LLM01",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.5",
    ),
    Family(
        id="history_injection",
        name="Conversation history injection (forged system / assistant / tool turns)",
        owasp="LLM01",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.5",
    ),
    Family(
        id="oob_exfiltration",
        name="Attacker web content and out-of-band exfiltration (agents that fetch URLs)",
        owasp="LLM01, LLM02, ASI01",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.5",
    ),
    Family(
        id="info_disclosure",
        name="System prompt / secret / PII leakage",
        owasp="LLM02, LLM07",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.1",
    ),
    Family(
        id="output_handling",
        name="Unsafe output handling (exfiltration)",
        owasp="LLM05",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.1",
    ),
    Family(
        id="resource_abuse",
        name="Unbounded consumption",
        owasp="LLM10",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.1",
    ),
    Family(
        id="rag_poisoning",
        name="RAG and vector poisoning",
        owasp="LLM08",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.2",
    ),
    Family(
        id="multi_turn",
        name="Multi-turn escalation",
        owasp="LLM01",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.2",
    ),
    Family(
        id="task_utility",
        name="Task utility / over-refusal",
        owasp="utility",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.2",
    ),
    Family(
        id="agent_goal_hijack",
        name="Agent goal hijack and tool misuse",
        owasp="LLM06, ASI01",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.3",
    ),
    Family(
        id="mcp_attacks",
        name="MCP: tool poisoning, rug pull, shadowing, confused deputy",
        owasp="LLM06",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.3",
    ),
    Family(
        id="agent_handoff",
        name="Multi-chain / handoff injection",
        owasp="ASI01",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.4",
    ),
    Family(
        id="jailbreak",
        name="Jailbreak and harmful content",
        owasp="LLM01",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.4",
        opt_in=True,
    ),
    Family(
        id="business_integrity",
        name="Business integrity / policy abuse",
        owasp="ASI / brand",
        status=FAMILY_STATUS_AVAILABLE,
        target_release="0.4",
        opt_in=True,
    ),
)

FAMILY_BY_ID = {f.id: f for f in FAMILIES}
