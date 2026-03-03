"""
Tool Firewall — enforces a per-tool allowlist policy.

Currently supported tools:
  - http_fetch: checked against allowed_domains list
  - (any other tool): denied by default with TOOL-002

Domain matching supports exact matches and sub-domains:
  allowed: "example.com"  →  matches "example.com" and "api.example.com"
"""
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse

from app.policy import ToolsPolicy


@dataclass
class FirewallResult:
    decision: str          # "ALLOW" | "TOOL_DENY"
    reason_codes: List[str] = field(default_factory=list)
    reason: str = ""


def _domain_allowed(hostname: str, allowed: List[str]) -> bool:
    """
    Return True if *hostname* exactly matches or is a sub-domain of any entry
    in *allowed*.
    """
    hostname = hostname.lower()
    for entry in allowed:
        entry = entry.lower()
        if hostname == entry or hostname.endswith("." + entry):
            return True
    return False


def check_tool(tool_name: str, arguments: dict, policy: ToolsPolicy) -> FirewallResult:
    """
    Validate a tool invocation against the firewall policy.
    Returns ALLOW or TOOL_DENY with an appropriate reason code.
    """
    if tool_name == "http_fetch":
        url = arguments.get("url", "") or ""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if not hostname:
            return FirewallResult(
                decision="TOOL_DENY",
                reason_codes=[policy.http_fetch.deny_reason_code],
                reason="Tool request has no resolvable hostname",
            )

        if _domain_allowed(hostname, policy.http_fetch.allowed_domains):
            return FirewallResult(decision="ALLOW", reason="Domain is in allowlist")

        return FirewallResult(
            decision="TOOL_DENY",
            reason_codes=[policy.http_fetch.deny_reason_code],
            reason=f"Domain '{hostname}' is not in the allowed list",
        )

    # Unknown / unregistered tool — deny by default
    return FirewallResult(
        decision="TOOL_DENY",
        reason_codes=["TOOL-002"],
        reason=f"Tool '{tool_name}' is not registered in the firewall policy",
    )
