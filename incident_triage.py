"""Incident triage: investigate with tools, then diagnose. The trajectory is scored,
not just the answer.
"""

import json
import re
from collections.abc import Iterable

import verifiers.v1 as vf
from verifiers.v1.state import State

SYSTEM_PROMPT = """You are on call. A production incident has been reported.

Investigate using the tools available before answering. Do not guess - the first
explanation that fits is usually the symptom, not the cause.

When you are confident, reply with JSON only:

{
  "root_cause": "<short id from the candidates list>",
  "remediation": ["<step>", "<step>", ...],
  "why": "<one sentence>"
}

Remediation must list everything that has to be true for this not to recur, not
just what makes the alert stop."""


SCENARIO = {
    "name": "mail-delivery-failure",
    "brief": (
        "Outbound mail to external domains has been failing for about 48 hours. "
        "Internal service-to-service mail is unaffected. No alerts fired. "
        "Users report password resets and digest emails never arrive."
    ),
    "candidates": [
        "expired-tls-cert",
        "certmanager-solver-misconfig",
        "network-firewall-block",
        "mail-service-crashed",
        "recipient-servers-rejecting",
    ],
    "root_cause": "certmanager-solver-misconfig",
    "symptom_answer": "expired-tls-cert",
    "remediation_keys": {
        "cert-renews-itself": ["cert-manager", "certmanager", "solver", "renew"],
        "queue-drains": ["queue", "spool", "backlog", "drain"],
        "monitoring-fixed": ["prometheus", "scrape", "port", "podmonitor", "metric"],
        "alerting-added": ["alert", "alarm", "notify", "prometheusrule"],
    },
}


class TriageState(State):
    """Per-rollout state. Records what the agent actually looked at."""

    calls: list[str] = []
    saw_debug_logs: bool = False
    checked_cert_manager: bool = False
    checked_queue: bool = False
    checked_monitoring: bool = False


class TriageToolsetConfig(vf.ToolsetConfig):
    pass


class TriageToolset(vf.Toolset[TriageToolsetConfig, TriageState]):
    """MCP tools over a simulated broken mail stack."""

    TOOL_PREFIX = None

    @vf.tool
    def list_services(self) -> str:
        """List the services in the mail stack and their reported status."""
        self.state.calls.append("list_services")
        return json.dumps(
            {
                "maddy": "running (healthy)",
                "cert-manager": "running",
                "prometheus": "running",
                "loki": "running",
                "grafana": "running",
            }
        )

    @vf.tool
    def read_logs(self, service: str, level: str = "info") -> str:
        """Read recent logs for a service.

        Args:
            service: service name, e.g. maddy or cert-manager
            level: minimum log level to return - info, warn, error or debug.
                The deployed level is info; retry and queue activity is logged
                at debug and will not appear unless you ask for it.
        """
        self.state.calls.append(f"read_logs({service},{level})")
        svc = service.lower()
        lvl = level.lower()

        if svc == "maddy":
            lines = [
                "ERROR outbound: remote MTA rejected connection: tls: certificate has expired",
                "ERROR outbound: delivery attempt failed for 14 recipients",
                "INFO  inbound: accepted 312 messages",
            ]
            if lvl == "debug":
                self.state.saw_debug_logs = True
                lines += [
                    "DEBUG spool: queue depth 2147, oldest message age 47h",
                    "DEBUG spool: retry scheduled for 2147 messages, backoff 30m",
                    "DEBUG spool: no messages delivered to external domains in 48h",
                ]
            return "\n".join(lines)

        if svc in ("cert-manager", "certmanager"):
            return "\n".join(
                [
                    "WARN  Certificate maddy-outbound-tls: renewal failed, will retry",
                    "ERROR acme: DNS01 solver could not read credentials from secret 'dns-provider'",
                    "WARN  Certificate maddy-outbound-tls: 6 consecutive renewal failures",
                ]
            )

        return f"no recent entries for {service} at level {level}"

    @vf.tool
    def describe_certificate(self, name: str = "maddy-outbound-tls") -> str:
        """Show a TLS certificate's validity window and current status."""
        self.state.calls.append(f"describe_certificate({name})")
        return json.dumps(
            {
                "name": name,
                "not_after": "2026-09-30T04:11:00Z",
                "status": "Expired",
                "expired_hours_ago": 48,
                "used_by": "maddy outbound relay identity",
            }
        )

    @vf.tool
    def check_cert_manager(self, name: str = "maddy-outbound-tls") -> str:
        """Show the cert-manager Certificate resource: renewal state and solver config."""
        self.state.calls.append(f"check_cert_manager({name})")
        self.state.checked_cert_manager = True
        return json.dumps(
            {
                "name": name,
                "ready": False,
                "condition": "Failed",
                "message": "ACME DNS01 solver references secret 'dns-provider' which holds no provider credentials",
                "failing_for_days": 6,
                "last_successful_renewal": "2026-08-01T09:02:00Z",
            }
        )

    @vf.tool
    def queue_depth(self) -> str:
        """Report the current outbound spool queue depth."""
        self.state.calls.append("queue_depth")
        self.state.checked_queue = True
        return json.dumps(
            {"undelivered": 2147, "oldest_message_age_hours": 47, "trend": "rising"}
        )

    @vf.tool
    def prometheus_targets(self) -> str:
        """List Prometheus scrape targets and whether they are being collected."""
        self.state.calls.append("prometheus_targets")
        self.state.checked_monitoring = True
        return json.dumps(
            [
                {
                    "job": "maddy",
                    "configured_port": 9100,
                    "service_exposes_port": 9154,
                    "state": "down",
                    "last_scrape_error": "connection refused",
                },
                {"job": "cert-manager", "configured_port": 9402, "state": "up"},
            ]
        )

    @vf.tool
    def list_alert_rules(self) -> str:
        """List configured Prometheus alerting rules for the mail stack."""
        self.state.calls.append("list_alert_rules")
        self.state.checked_monitoring = True
        return json.dumps({"rules": [], "note": "no PrometheusRule resources in namespace mail"})


def _parse(reply: str) -> dict:
    """Pull the JSON object out of a reply that may be wrapped in prose or fences."""
    match = re.search(r"\{.*\}", reply, re.S)
    if not match:
        return {}
    try:
        parsed = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _remediation_text(parsed: dict) -> str:
    steps = parsed.get("remediation", [])
    if isinstance(steps, str):
        steps = [steps]
    return " ".join(str(s) for s in steps).lower()


class TriageConfig(vf.TaskConfig):
    tools: TriageToolsetConfig = TriageToolsetConfig()
    min_tool_calls: int = 3


class TriageData(vf.TaskData):
    candidates: list[str]
    root_cause: str
    symptom_answer: str
    remediation_keys: dict[str, list[str]]


class TriageTask(vf.Task[TriageData, TriageState, TriageConfig]):
    @classmethod
    def toolsets(cls, config: TriageConfig) -> list[vf.Toolset]:
        return [TriageToolset(config.tools)]

    @vf.reward(weight=1.0)
    async def correct_root_cause(self, trace: vf.Trace) -> float:
        """Full credit only for the underlying cause."""
        answer = _parse(trace.last_reply).get("root_cause", "")
        return float(str(answer).strip().lower() == self.data.root_cause.lower())

    @vf.reward(weight=-0.5)
    async def stopped_at_symptom(self, trace: vf.Trace) -> float:
        """Penalty for naming the visible symptom instead of the cause."""
        answer = _parse(trace.last_reply).get("root_cause", "")
        return float(str(answer).strip().lower() == self.data.symptom_answer.lower())

    @vf.reward(weight=0.5)
    async def complete_remediation(self, trace: vf.Trace) -> float:
        """Fraction of the things that must be true for this not to recur."""
        text = _remediation_text(_parse(trace.last_reply))
        if not text:
            return 0.0
        hits = sum(
            1
            for words in self.data.remediation_keys.values()
            if any(w in text for w in words)
        )
        return hits / len(self.data.remediation_keys)

    @vf.reward(weight=0.3)
    async def found_hidden_evidence(self, trace: vf.Trace) -> float:
        """Credit for asking for debug logs, the only way to see the queue."""
        return float(self._called(trace, "read_logs", "debug"))

    @vf.reward(weight=-0.3)
    async def guessed_without_looking(self, trace: vf.Trace) -> float:
        """Penalty for answering on too little investigation, right or wrong."""
        return float(self._tool_call_count(trace) < self.config.min_tool_calls)

    @staticmethod
    def _tool_calls(trace: vf.Trace) -> list:
        out = []
        for msg in trace.assistant_messages:
            out.extend(getattr(msg, "tool_calls", None) or [])
        return out

    @classmethod
    def _tool_call_count(cls, trace: vf.Trace) -> int:
        return len(cls._tool_calls(trace))

    @classmethod
    def _called(cls, trace: vf.Trace, name: str, *args_contain: str) -> bool:
        for call in cls._tool_calls(trace):
            fn = getattr(call, "function", None) or call
            called_name = str(getattr(fn, "name", "") or "")
            raw_args = getattr(fn, "arguments", "") or ""
            blob = f"{called_name} {raw_args}".lower()
            if name.lower() in called_name.lower() and all(
                a.lower() in blob for a in args_contain
            ):
                return True
        return False


class TriageTasksetConfig(vf.TasksetConfig):
    task: TriageConfig = TriageConfig()


class TriageTaskset(vf.Taskset[TriageTask, TriageTasksetConfig]):
    def load(self) -> Iterable[TriageTask]:
        s = SCENARIO
        options = ", ".join(s["candidates"])
        prompt = (
            f"Incident report:\n{s['brief']}\n\n"
            f"Investigate with the tools available, then report the root cause.\n\n"
            f"Candidate causes: {options}"
        )
        yield TriageTask(
            TriageData(
                idx=0,
                name=s["name"],
                prompt=prompt,
                system_prompt=SYSTEM_PROMPT,
                candidates=s["candidates"],
                root_cause=s["root_cause"],
                symptom_answer=s["symptom_answer"],
                remediation_keys=s["remediation_keys"],
            ),
            self.config.task,
        )


__all__ = ["TriageTaskset", "TriageTasksetConfig", "TriageToolset"]
