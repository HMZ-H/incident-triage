import asyncio
import json

import verifiers.v1 as vf
from incident_triage import TriageTaskset, TriageTasksetConfig

task = list(TriageTaskset(TriageTasksetConfig(id="incident-triage")))[0]


def mk(tool_calls, final_reply):
    tr = vf.Trace(
        task=vf.TraceTask(type="TriageTask", data=task.data),
        agent=vf.AgentInfo(config=vf.AgentConfig(), name="test", trainable=False),
    )
    for i, (name, args) in enumerate(tool_calls):
        tr.nodes.append(
            vf.MessageNode(
                message=vf.AssistantMessage(
                    content="",
                    tool_calls=[
                        vf.ToolCall(id=f"c{i}", name=name, arguments=json.dumps(args))
                    ],
                ),
                sampled=True,
            )
        )
    tr.nodes.append(
        vf.MessageNode(message=vf.AssistantMessage(content=final_reply), sampled=True)
    )
    return tr


FULL = [
    ("list_services", {}),
    ("read_logs", {"service": "maddy", "level": "info"}),
    ("describe_certificate", {"name": "maddy-outbound-tls"}),
    ("check_cert_manager", {"name": "maddy-outbound-tls"}),
    ("read_logs", {"service": "maddy", "level": "debug"}),
    ("queue_depth", {}),
    ("prometheus_targets", {}),
    ("list_alert_rules", {}),
]

SHALLOW = [
    ("read_logs", {"service": "maddy", "level": "info"}),
    ("describe_certificate", {"name": "maddy-outbound-tls"}),
]

GOOD = json.dumps({
    "root_cause": "certmanager-solver-misconfig",
    "remediation": [
        "Fix the ACME DNS01 solver to point at a secret with real credentials so cert-manager renews on its own",
        "Drain the outbound spool queue and confirm delivery in the logs",
        "Correct the Prometheus scrape port so queue depth is collected",
        "Add alert rules for certificate expiry and queue depth",
    ],
    "why": "renewal has been failing silently for six days",
})

PARTIAL = json.dumps({
    "root_cause": "certmanager-solver-misconfig",
    "remediation": ["Fix the cert-manager solver so renewal works"],
    "why": "renewal broken",
})

SYMPTOM = json.dumps({
    "root_cause": "expired-tls-cert",
    "remediation": ["Replace the expired certificate"],
    "why": "the cert expired",
})

W = {
    "correct_root_cause": 1.0,
    "stopped_at_symptom": -0.5,
    "complete_remediation": 0.5,
    "found_hidden_evidence": 0.3,
    "guessed_without_looking": -0.3,
}


async def score(label, trace):
    parts = {k: await getattr(task, k)(trace) for k in W}
    total = sum(W[k] * v for k, v in parts.items())
    detail = "  ".join(f"{k.split('_')[0]}={v:.2f}" for k, v in parts.items())
    print(f"{label:<28} {detail}   total={total:+.2f}")


async def main():
    print(f"task: {task.data.name}\n")
    await score("investigated, full fix", mk(FULL, GOOD))
    await score("investigated, partial fix", mk(FULL, PARTIAL))
    await score("lucky guess, no tools", mk([], GOOD))
    await score("investigated, symptom", mk(FULL, SYMPTOM))
    await score("shallow look, symptom", mk(SHALLOW, SYMPTOM))
    await score("no tools, symptom", mk([], SYMPTOM))


asyncio.run(main())
