# incident-triage

### Overview
- **Environment ID**: `incident-triage`
- **Short description**: Multi-turn incident investigation over MCP tools. The evidence is hidden behind correct tool use, and the trajectory is scored, not just the answer.
- **Tags**: mcp, tool-use, multi-turn, debugging, devops, sre, agentic, eval, train

### Motivation

Most agentic evals score the final string. An agent that guesses correctly scores
the same as one that worked it out. In a real incident those are not the same
outcome — one of them will be wrong next time, and you have no way of knowing
which.

This environment scores both. The agent is dropped into a broken mail stack and
given tools. The cause is reachable, but only by asking the right questions.

The important detail: the deployed log level is info, and the queue backlog is
logged at debug. An agent that reads the logs and stops sees an expired
certificate and nothing else. It concludes the certificate expired, which is true,
and replaces it, which fixes nothing — cert-manager has been failing to renew for
six days, and the same outage returns in ninety.

The only way to see the 2,147 undelivered messages is to ask for debug logs. That
is the single call that separates investigation from pattern-matching.

### Tools

Exposed as MCP tools via `@vf.tool` on a `Toolset`.

| Tool | What it reveals |
| --- | --- |
| `list_services` | Everything reports healthy. A dead end, deliberately. |
| `read_logs(service, level)` | At info: the expired cert. At debug: the queue. |
| `describe_certificate(name)` | Expired 48 hours ago. The symptom. |
| `check_cert_manager(name)` | Renewal failing 6 days; DNS01 solver points at a secret with no credentials. The cause. |
| `queue_depth` | 2,147 undelivered, oldest 47h, rising. |
| `prometheus_targets` | Scrape on 9100, service exposes 9154. Monitoring was blind. |
| `list_alert_rules` | None exist. Which is why nobody was paged. |

### Task
- **Type**: multi-turn with tool use
- **Output format**: JSON with `root_cause`, `remediation` (list), and `why`.

### Rubric

| Reward function | Weight | Fires when |
| --- | --- | --- |
| `correct_root_cause` | +1.0 | Names the cert-manager renewal failure |
| `stopped_at_symptom` | -0.5 | Names the expired certificate instead |
| `complete_remediation` | +0.5 | Fraction of: renewal fixed, queue drained, monitoring corrected, alerting added |
| `found_hidden_evidence` | +0.3 | Called `read_logs` at debug level |
| `guessed_without_looking` | -0.3 | Answered on fewer than `min_tool_calls` tool calls |

### What the scores look like

Verified against synthetic trajectories in `test_triage.py`, no model needed:

| Trajectory | Total |
| --- | --- |
| investigated, full fix | +1.80 |
| investigated, partial fix | +1.43 |
| lucky guess, no tools | +1.20 |
| investigated, symptom | -0.20 |
| shallow look, symptom | -0.80 |
| no tools, symptom | -0.80 |

The row worth reading is the third. A correct answer reached without calling a
single tool scores below a half-correct answer reached by investigating. That is
deliberate. Being right by luck is not a repeatable skill, and rewarding it trains
the wrong behaviour.

### Metrics

| Metric | Meaning |
| ------ | ------- |
| `reward` | Weighted sum |
| `correct_root_cause` | Fraction naming the underlying cause |
| `stopped_at_symptom` | Fraction caught by the certificate decoy |
| `found_hidden_evidence` | Fraction that asked for debug logs — the investigation signal |
| `guessed_without_looking` | Fraction that answered without looking |
| `complete_remediation` | How much of the real fix was named |

`found_hidden_evidence` is the one to watch. A model can score reasonably on
`correct_root_cause` while almost never earning this, which tells you it is
recognising a familiar scenario rather than diagnosing one.

### Extending

Add a scenario to `SCENARIO`, give the toolset the data to serve it, and set
`remediation_keys` to the things that must be true for the incident not to recur.
The decoy should be genuinely supported by what the default-level tools return —
if it is obviously wrong, the task measures nothing.
