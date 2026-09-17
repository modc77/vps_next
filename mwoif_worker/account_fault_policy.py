from __future__ import annotations

from dataclasses import dataclass

_ACCOUNT_FAULT = {
    "DEVPLAY_LOGIN_RESPONSE_INVALID",
    "DEVPLAY_LOGIN_FAILED",
    "SENDER_LOGIN_FAILED",
    "ORPHAN_SENDER_LOGIN_FAILED",
}
_NETWORK_FAULT = {
    "DEVPLAY_TIMEOUT",
    "DEVPLAY_NETWORK_ERROR",
    "DEVPLAY_LOGIN_HTTP_RETRYABLE",
    "DEVPLAY_LOGIN_REDIRECT_BLOCKED",
    "HEARTBEAT_NETWORK_ERROR",
    "CLAIM_NETWORK_ERROR",
}
_RECEIVER_FAULT = {
    "RECEIVER_LOGIN_FAILED",
    "RECEIVER_CREDENTIAL_INVALID",
    "RECEIVER_SESSION_INVALID",
}


@dataclass(frozen=True, slots=True)
class FaultDecision:
    error_class: str
    action: str
    retryable: bool


def classify(code: str, retryable: bool = False) -> FaultDecision:
    value = str(code or "").strip().upper()
    if value in _ACCOUNT_FAULT:
        return FaultDecision("account_fault", "disable", False)
    if value in _NETWORK_FAULT or value.endswith("_NETWORK_ERROR") or value.endswith("_TIMEOUT"):
        return FaultDecision("network_fault", "cooldown", True)
    if value in _RECEIVER_FAULT or value.startswith("RECEIVER_"):
        return FaultDecision("receiver_fault", "pause", bool(retryable))
    if retryable:
        return FaultDecision("retryable_stage_fault", "retry", True)
    if value.startswith("FATAL_"):
        return FaultDecision("fatal_job_fault", "pause", False)
    return FaultDecision("unknown", "manual_review", bool(retryable))
