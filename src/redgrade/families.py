"""Attack families and their mapping to OWASP Top 10 for LLM Applications (2025) and the
OWASP Top 10 for Agentic Applications (2026).

``status`` says whether the repository ships attacks for the family. Families marked
``planned`` appear in the report's coverage matrix so a green run is never read as
"everything was tested".
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Family:
    id: str
    name: str
    owasp: str
    status: str  # available | planned
    target_release: str


FAMILIES: tuple[Family, ...] = (
    Family("prompt_injection_direct", "Direct prompt injection", "LLM01", "available", "0.1"),
    Family("prompt_injection_indirect", "Indirect prompt injection", "LLM01", "available", "0.1"),
    Family("info_disclosure", "System prompt / secret / PII leakage", "LLM02, LLM07", "available", "0.1"),
    Family("output_handling", "Unsafe output handling (exfiltration)", "LLM05", "available", "0.1"),
    Family("resource_abuse", "Unbounded consumption", "LLM10", "available", "0.1"),
    Family("rag_poisoning", "RAG and vector poisoning", "LLM08", "planned", "0.2"),
    Family("agent_goal_hijack", "Agent goal hijack and tool misuse", "LLM06, ASI01", "planned", "0.3"),
    Family(
        "mcp_attacks", "MCP: tool poisoning, rug pull, shadowing, confused deputy", "LLM06", "planned", "0.3"
    ),
    Family("jailbreak", "Jailbreak and harmful content", "LLM01", "planned", "0.4"),
)

FAMILY_BY_ID = {f.id: f for f in FAMILIES}
