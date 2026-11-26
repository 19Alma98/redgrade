"""What to change in the agent when an attack family gets through.

Short, concrete starting points for the AI engineer who reads a finding. They are not a
guarantee: re-run the scan (or replay the finding) after every fix, because a defense that stops
one phrasing often lets the next one through.
"""

from redgrade.models import Attack

REMEDIATION: dict[str, str] = {
    "prompt_injection_direct": (
        "Keep the system prompt authoritative: restate the role and refusal rules after user content, "
        "never let user text redefine the role, and add an input classifier for override / role-play / "
        "encoded instructions. Do not rely on 'ignore previous instructions' keyword filters alone."
    ),
    "prompt_injection_indirect": (
        "Treat documents, retrieved chunks and tool results as data, never as instructions: wrap them in "
        "clearly delimited blocks (spotlighting / datamarking), tell the model that text inside them has "
        "no authority, and scan untrusted content for instructions before it reaches the model."
    ),
    "file_attachments": (
        "Normalize uploads before extraction: drop metadata, comments, hidden / white / tiny / off-page "
        "text and invisible HTML, then treat the extracted text as untrusted data (same rules as "
        "indirect injection). Test with the real extractor your pipeline uses."
    ),
    "history_injection": (
        "Do not trust conversation history sent by the client: keep it server-side (session id) or sign "
        "it, reject client-supplied system / tool / assistant turns, and re-apply the system prompt on "
        "every request."
    ),
    "oob_exfiltration": (
        "Restrict what the agent can fetch and where it can send data: an allowlist of hosts for fetch "
        "tools, no URLs built from conversation data, and egress filtering on the agent's network."
    ),
    "info_disclosure": (
        "Assume the system prompt will leak: move secrets, keys and internal data out of it, fetch "
        "per-user data with the caller's permissions only, and add an output filter for secrets and PII."
    ),
    "output_handling": (
        "Do not render model-controlled links and images to external hosts: allowlist image / link "
        "domains in the UI (Content-Security-Policy), strip query strings, and never auto-load remote "
        "images from model output."
    ),
    "output_injection": (
        "Treat model output as untrusted input downstream: HTML-escape before rendering, use "
        "parameterized SQL, never pass output to a shell or template engine, and neutralize spreadsheet "
        "formulas in exports."
    ),
    "resource_abuse": (
        "Cap what one request can cost: max output tokens, max tool calls and loop iterations per turn, "
        "request timeouts and per-user rate limits."
    ),
    "rag_poisoning": (
        "Control what enters the index (provenance, write permissions, content scanning), filter "
        "retrieval by the caller's access rights, and treat retrieved chunks as untrusted data."
    ),
    "multi_turn": (
        "Evaluate the whole conversation, not only the last message: re-check the goal of the dialogue "
        "on every turn, cap conversation length, and run the input classifier on the accumulated context."
    ),
    "agent_goal_hijack": (
        "Bind tools to the user's task: least-privilege tool set per task, argument validation on the "
        "server side, and human confirmation for irreversible or out-of-scope actions."
    ),
    "mcp_attacks": (
        "Pin and review tool descriptions (hash them and alert on change), namespace tools per server, "
        "never let one tool's description call another, and show the user which server a tool belongs to."
    ),
    "agent_handoff": (
        "Authenticate and validate messages between agents: a typed schema for handoffs, no free-text "
        "instructions carried across agents, and each agent keeps its own permissions."
    ),
    "access_control": (
        "Enforce authorization in the tools, not in the prompt: every tool checks the authenticated "
        "caller's identity and role on every object and function (BOLA / BFLA), whatever the model asks."
    ),
    "memory_poisoning": (
        "Write to long-term memory only through validated, typed operations; scope memory per user, "
        "mark its provenance, and never store instructions that came from untrusted content."
    ),
    "user_manipulation": (
        "Ground claims and actions in verified data, show sources, and require explicit user "
        "confirmation before actions the user did not ask for."
    ),
    "tool_output_injection": (
        "Treat every tool result as untrusted data: return typed, structured fields instead of free text, "
        "mark tool output as data (spotlighting), and after a tool result is read only allow the tools "
        "the user's task needs (plan first, then execute; no new destinations from tool content)."
    ),
    "task_aligned_injection": (
        "Do not let content correct itself: when a document contains notes 'for the AI' or 'corrected' "
        "values, quote the source values and flag the conflict to the user instead of picking one; cross-"
        "check numbers against structured data and cite where each claim comes from."
    ),
    "instruction_file_poisoning": (
        "Load skills and instruction files only from trusted, pinned sources; review them like code (hash "
        "and alert on change), never run helper scripts or install commands they ask for without "
        "confirmation, and keep repository files (READMEs, rules files) out of the instruction channel."
    ),
    "coding_agent": (
        "Run the agent in a sandbox without secrets in the environment, treat terminal and test output as "
        "data, require review for changes to tests, CI and config, and block network egress and reads of "
        "credential files (.env, ~/.ssh, cloud credentials)."
    ),
    "denial_of_wallet": (
        "Cap each request: maximum tool calls, loop iterations and tokens per turn, a time budget, and "
        "detection of repeated identical calls; never let tool content decide how many more calls to make."
    ),
    "jailbreak": (
        "Add a dedicated harmful-content classifier on input and output (the model's own refusal is not "
        "enough), and evaluate the conversation as a whole for role-play and fiction framings."
    ),
    "business_integrity": (
        "Encode business rules (prices, discounts, refunds, commitments) in code that the agent calls, "
        "not in the prompt; the model can describe a policy but must not be able to change it."
    ),
}

_DEFAULT = (
    "Add the attack to your regression pack, change the agent (prompt, tools, filters) and replay it "
    "until it is resisted in every trial."
)


def remediation_for(attack: Attack) -> str:
    """Suggested fix for a successful attack (by family)."""
    return REMEDIATION.get(attack.family, _DEFAULT)
