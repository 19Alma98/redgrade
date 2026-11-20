"""Who the attacker is, and whose data it must never reach (access-control attacks).

Access-control attacks (BOLA, BFLA, RBAC, privilege escalation) only make sense against real
identities: the attacker is logged in as one user and tries to reach another user's objects or a
function reserved to a more privileged role. ``Identity`` describes those identities; attack
payloads and detector patterns reference them with placeholders, expanded per trial:

==================  =====================================================================
``{USER_ID}``       the attacker's own id (the account the target is called as)
``{VICTIM_ID}``     another real user's id the attacker must never reach
``{USER_ROLE}``     the attacker's role (e.g. ``customer``)
``{ADMIN_ROLE}``    a privileged role the attacker must never obtain (e.g. ``admin``)
==================  =====================================================================

``victim_data`` lists strings that only appear in the victim's records (an email, an order
number, an IBAN): if the reply contains one, data crossed the tenant boundary. The defaults are
placeholders that work with the offline demo; set real values in ``redgrade.yaml``::

    identity:
      user_id: "C-1001"
      victim_id: "C-2002"
      role: customer
      admin_role: admin
      victim_data: ["giulia.neri@example.com", "ORD-77812"]
"""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["IDENTITY_PLACEHOLDERS", "Identity", "current_identity", "expand_identity", "identity_scope"]


class Identity(BaseModel):
    model_config = ConfigDict(frozen=True)

    user_id: str = "user-1001"
    victim_id: str = "user-2002"
    role: str = "customer"
    admin_role: str = "admin"
    victim_data: list[str] = Field(default_factory=list)

    def placeholders(self) -> dict[str, str]:
        return {
            "{USER_ID}": self.user_id,
            "{VICTIM_ID}": self.victim_id,
            "{USER_ROLE}": self.role,
            "{ADMIN_ROLE}": self.admin_role,
        }


IDENTITY_PLACEHOLDERS: tuple[str, ...] = tuple(Identity().placeholders())

_IDENTITY: ContextVar[Identity] = ContextVar("redgrade_identity", default=Identity())  # noqa: B039


def current_identity() -> Identity:
    """Identity used to expand placeholders in the current trial."""
    return _IDENTITY.get()


@contextmanager
def identity_scope(identity: Identity | None) -> Iterator[None]:
    """Expand identity placeholders from ``identity`` while one trial runs (context local)."""
    if identity is None:
        yield
        return
    token = _IDENTITY.set(identity)
    try:
        yield
    finally:
        _IDENTITY.reset(token)


def expand_identity(text: str) -> str:
    if "{" not in text:
        return text
    for key, value in current_identity().placeholders().items():
        if key in text:
            text = text.replace(key, value)
    return text
