# Architecture notes

This is the internals doc — how this port differs from the original
implementation and why, what's deliberately deferred, and what to verify
before this handles production traffic. If you just want to install and
run TruClaw, see `README.md` instead; nothing here is required reading for
that.

## Where the enforcement point moved

The original implementation hooked `before_tool_callback` on a live Google
ADK agent tree in-process. That only ever covers agents built on ADK.

This port moves the hook to an **AgentCore Gateway REQUEST interceptor**
(`interceptor/handler.py`) — it fires for every tool call the Gateway
routes, regardless of which framework built the calling agent. That's the
difference between "this agent has guardrails" and "this governs every
agent behind the Gateway."

## Module map back to the original implementation

| Original | This repo | Changed? |
|---|---|---|
| `config.py` | `truclaw_aws/config.py` | S3 bucket instead of GCS bucket; adds `ESCALATION_STATE_MACHINE_ARN` |
| `gcs_storage.py` | `truclaw_aws/s3_storage.py` | GCS -> S3; adds byte-level put/get/list helpers used by the per-object storage below |
| `jwt_verify.py` | `truclaw_aws/jwt_verify.py` | Unchanged logic (pure crypto, no cloud dependency) |
| `pairing.py` | `truclaw_aws/pairing.py` | **Redesigned**: one S3 object per paired device instead of one shared blob mutated on every pairing event — removes a read-modify-write race, see below |
| `ledger.py` | `truclaw_aws/ledger.py` | **Redesigned**: one immutable S3 object per event instead of re-uploading a growing shared blob on every write — removes a real data-loss bug under concurrent writers, see below |
| `policy.py` | `truclaw_aws/policy.py` | Same single-object-per-agent shape — policy edits are human-gated and infrequent, so there's no race to fix here |
| `danger.py` | `truclaw_aws/danger.py` | Same three-question rubric and Gemini call; a Bedrock model swap is an unwired stub, not used by default |
| `guardrail.py` + `protect.py` + `autopatch.py` | `interceptor/handler.py` | **Re-homed** from an ADK in-process monkeypatch to an AgentCore Gateway interceptor |
| `challenge.py` | `escalation/send_challenge.py` + `escalation/resume_handler.py` + `statemachine/escalation.asl.json` | **Re-homed** from in-process polling (asyncio + a module-level dict) to a Step Functions callback (`waitForTaskToken`) |
| `cron_aggregator.py` (a Cloud Run Job) | `aggregator/handler.py` (an EventBridge-scheduled Lambda) | Same aggregation logic, reads the new per-event ledger objects |
| `admin_cli.py` | `admin/cli.py` | Same commands, S3-backed |
| `chat_handler.py`, `pair_route.py`, original `cli.py` | *(not ported)* | FastAPI/Google-Chat-specific glue, out of scope for the Gateway-interceptor design |

## Why the ledger and pairing storage changed shape

The original stored *all* paired devices, and the *entire* ledger, as one
shared blob each, mutated with a read-modify-write on every write (load the
whole thing, change one entry, re-upload the whole thing). Under concurrent
writers that's a real race: whichever process uploads last silently drops
the others' writes from the canonical copy. It also meant re-uploading an
ever-growing file on every single ledger event.

This port gives every item its own object instead:

- **Ledger**: `truclaw/policies/<agentId>/ledger/<yyyy>/<mm>/<dd>/<epoch_ms>-<uuid8>.json`,
  one immutable object per decision. Nothing to overwrite, so nothing to
  race. The date-prefixed key also means reads (`read_events`,
  `prior_summary`, the aggregator) list a bounded recent window instead of
  scanning the whole history.
- **Pairing**: `truclaw/pairing/<userId>/<publicKeyHash>.json`, one object
  per device. `save_pairing` is a single PUT, no read-modify-write at all.

`memory.md` and `usage_summary.json` keep the original single-object shape
— they have exactly one writer (the aggregator Lambda), so there's nothing
to race there.

## The escalation design

Common case (allow/deny) stays synchronous and cheap — no Step Functions
involved. Only when a call needs human sign-off does the interceptor start
a **Step Functions STANDARD** execution (`statemachine/escalation.asl.json`)
that sends the push notification and waits on a task token, bounded by
`TRUCLAW_CHALLENGE_TIMEOUT_SECONDS` (default 120s). The wait state lives in
Step Functions, not in a Lambda's memory — any warm or cold
`resume_handler.py` invocation can resolve any pending approval, because
the task token, not local process state, is what Step Functions uses to
find the paused execution.

Standard, not Express: this started out as an Express Sync execution
(bounded, blocking, cheap), which would have been the simpler design. It
doesn't work — Express workflows, sync or async, don't support the
`.waitForTaskToken` integration pattern at all, which came back as a
`CREATE_FAILED` / `SCHEMA_VALIDATION_FAILED` error on an actual deploy, not
something caught in review. Standard is the only state machine type that
supports pausing on a task token, which the whole escalation flow depends
on. The cost of that: Standard has no `StartSyncExecution` API, so
`interceptor/handler.py:_escalate()` starts the execution with
`StartExecution` and polls `DescribeExecution` in a short loop (2s
interval) until it resolves or the deadline passes, rather than blocking on
one synchronous call. Still synchronous from the Gateway's point of view —
the interceptor doesn't return until it has an answer — just implemented as
a poll against Step Functions' own durable execution state instead of an
API that turned out not to support this pattern.

This bounded-wait design (Standard + poll, capped around 130s including
margin) is a fit for short challenge windows. It stops being a fit if
approvals ever need a longer SLA (e.g. routed to an on-call rotation
instead of an account owner's phone) — that would need a fully async
"return pending, caller retries" model instead. Not built here; the seam
for it is that only `escalation/send_challenge.py` would need to change,
not the interceptor's overall shape or the state machine.

## Cedar / AgentCore Policy — kept deliberately separate

Cedar (and AgentCore Policy, which is built on it) is an authorization
language: binary permit/deny, evaluated fresh per request, no memory of
prior calls, no way to express "pause for human judgment." It's the right
tool for **coarse authorization** — can this agent principal even attempt
this class of action at all (resource ownership, business hours, coarse
segregation of duties) — and the wrong tool for **risk decisioning**,
which is what `danger.py`/`policy.py`/`ledger.py` actually do: stateful
thresholds, cumulative-pattern detection, and free-text business rules
handed to an LLM for judgment calls. Real fraud/risk systems in banking
draw exactly this line — authorization and fraud/risk decisioning are
built as separate systems, not one doing both jobs.

The `cedar/` directory in this repo contains an earlier exploration that
translated the *full* policy — including `toolThresholds` and
`alwaysDangerousTools` — into Cedar, using a `context.humanApproved` flag
as a workaround for Cedar having no native escalation verdict. That
approach works, but it strains Cedar into a role it isn't built for. The
current direction is narrower and cleaner: keep all risk-tiering logic
exactly where it is in `danger.py`/`policy.py` (unchanged, no Cedar
involved), and reserve Cedar/AgentCore Policy for a separate, much smaller
set of genuinely static authorization facts that don't change when
transaction risk logic changes. That authorization layer isn't built yet
— `cedar/` should be read as a mapping-feasibility sketch, not the
intended production design.

## Attaching the interceptor to a real Gateway (resolved)

This was flagged as an open question and is now confirmed against AWS's
own API reference, not guessed. Neither CLI tool supports configuring
interceptors: the deprecated `bedrock-agentcore-starter-toolkit` has no
interceptor-related command at all, and the current `@aws/agentcore` CLI's
own docs say so explicitly — "With the AgentCore CLI, first create and
deploy the gateway, then configure interceptors using the AWS CLI or AWS
Python SDK (Boto3)." Interceptor configuration is a parameter on the raw
`create-gateway`/`update-gateway` API operations
(`GatewayInterceptorConfiguration`), not a separate resource or command:

```
aws bedrock-agentcore-control update-gateway \
  --gateway-identifier <gateway-id> \
  --interceptor-configurations '[{
      "interceptor": {"lambda": {"arn": "<interceptor Lambda ARN>"}},
      "interceptionPoints": ["REQUEST"],
      "inputConfiguration": {"passRequestHeaders": false}
  }]'
```

See `infra/scripts/setup_agentcore.sh` for the full sequence (create the
Gateway and its IAM role via the `agentcore` CLI, register tool targets,
then this raw `update-gateway` call for the interceptor attachment itself).

What's still genuinely unverified: the exact request/response JSON shape
the interceptor Lambda receives and must return (`passRequestHeaders`
controls whether headers are included, but the full payload schema wasn't
pinned down from the docs fetched so far). `interceptor/handler.py`'s
`_parse_gateway_event` and `_gateway_response` remain written against the
documented *concept*, not a verified field-for-field schema — confirm
against a real invocation (CloudWatch logs from a live test call) before
trusting the identity/tool-name extraction in production. The decision
logic in between (the actual hook design) doesn't need to change regardless
of how those two functions end up being adjusted.

There's also a CDK alpha module specifically for this —
`@aws-cdk/aws-bedrock-agentcore-alpha` — which reportedly supports
attaching a Lambda interceptor as a first-class construct with automatic
IAM permission grants. Not adopted here yet (alpha-versioned, and its exact
Python API wasn't verified before this was written), but worth evaluating
as a follow-up to fold Gateway + interceptor creation into
`infra/cdk/truclaw_stack.py` directly instead of the separate imperative
script, for the same reason everything else in this repo is CDK-managed
rather than click-ops or one-off CLI commands.

## What's deliberately not built yet

- **Cedar-based coarse authorization** (see above) — a real hardening
  step, scoped separately from this repo's risk-decisioning logic.
- **On-call / escalation-chain routing.** `escalation/send_challenge.py`
  pushes to the account owner's own paired device(s) only. Swapping this
  for an ops/compliance on-call queue only requires changing that one
  function — the state machine and interceptor don't know or care what
  "ask a human" means underneath.
- **A Bedrock-hosted classifier model.** `danger.py` keeps calling Gemini
  directly. `_bedrock_generate` is a stub, not wired in, not exercised
  against a live endpoint.

## Cost detail

Pulled from AWS's published AgentCore pricing (verify current rates before
committing): Gateway is $0.005 per 1,000 tool invocations, Policy
authorization is $0.000025 per request, Identity is free when used through
Runtime/Gateway, and Runtime is $0.0895/vCPU-hour + $0.00945/GB-hour billed
per second with no CPU charge during I/O wait. Step Functions Standard
workflows are billed per state transition (not per-request the way Express
is) — the escalation workflow here is only a couple of transitions per
execution, and only escalated calls start an execution at all, so this
stays inside or close to the free tier at pilot volume. Lambda has its own
meaningful always-free tier on top of that. At pilot scale (order 10,000
tool calls/month) this is a
single-digit-to-$20/month bill, dominated by CloudWatch log volume and
whatever LLM the classifier calls. Re-estimate once you have a real
production call-volume number — every component here is linear and cheap
per unit.

## Tests

```
pip install -r requirements.txt
pytest tests/
```

Covers the threshold/policy logic and the classifier's JSON-extraction
helpers, without touching AWS or calling a live model. There's
deliberately no integration test against a real Gateway/Runtime/Step
Functions setup yet — add one once the open question above is resolved
against a real account.
