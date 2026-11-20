"""Crescendo multi-turn attacker (kept as a module for import compatibility).

The implementation lives in :mod:`redgrade.deep.conversational`, shared with GOAT and Echo Chamber.
"""

from redgrade.deep.conversational import CrescendoAttacker

CRESCENDO_SYSTEM = CrescendoAttacker.system_prompt

__all__ = ["CRESCENDO_SYSTEM", "CrescendoAttacker"]
