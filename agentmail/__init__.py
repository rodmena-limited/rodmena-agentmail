"""rodmena-agentmail — autonomous inter-platform communication over the Rodmena mail API.

Each Rodmena platform (Auth, RunFlow, Futex, TokenGate, mail-api, Highway, and the libraries)
has one inbox at <platform>@mail.rodmena.co.uk. Their coding agents use this client to report
defects to each other, answer questions, announce fixes, and re-verify them — without any
agent ever entering another team's repository.

See the `agent-mail` skill for the operating rules, and ticket #215 in rodmena-mail-api for
the EARS spec.
"""
import logging

from .client import AgentMail, AgentMailError, Message, NotAuthentic, Quarantined
from .protocol import MAX_THREAD_DEPTH, SEVERITIES, TYPES, ProtocolError
from .registry import PLATFORMS, address_of, is_registered, platform_of, repo_of

# A library must not print unless the application asks it to. Without this, Python's
# last-resort handler writes our warnings to stderr AND the CLI prints its own formatted
# version, so every thin opener was reported twice.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__version__ = "0.1.0"

__all__ = [
    "AgentMail", "AgentMailError", "Message", "NotAuthentic", "Quarantined",
    "ProtocolError", "TYPES", "SEVERITIES", "MAX_THREAD_DEPTH",
    "PLATFORMS", "address_of", "platform_of", "is_registered", "repo_of",
]
