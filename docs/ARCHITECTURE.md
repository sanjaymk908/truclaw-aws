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

**Update — the event shape is now confirmed, via a real invocation, not
guessed.** The temporary raw-event diagnostic logging added earlier
(still present in `interceptor/handler.py`, not yet removed) captured
this real payload from the deployed Gateway for an MCP `initialize`
message:

```json
{
  "interceptorInputVersion": "1.0",
  "mcp": {
    "gatewayRequest": {
      "path": "/mcp", "httpMethod": "POST", "headers": {},
      "body": {"id": 0, "method": "initialize", "params": {...}, "jsonrpc": "2.0"},
      "context": null
    },
    "gatewayResponse": null,
    "rawGatewayRequest": {"body": "..."}
  }
}
```

The important thing this revealed, which the earlier guess completely
missed: **the interceptor fires on every MCP protocol message flowing
through the Gateway, not just tool invocations** — `initialize`,
`tools/list`, `notifications/initialized`, `ping`, etc. all hit the same
interceptor. Only `body.method == "tools/call"` has a tool name/arguments
to evaluate (per the MCP spec, that method's `params` are
`{"name": ..., "arguments": {...}}`). The first real invocation crashed
specifically because `_parse_gateway_event` had no concept of "this isn't
a tool call" — it always tried to extract a tool name and always called
`check_danger()`, which blew up on `None.split(".")` for an `initialize`
message. Fixed: `_parse_gateway_event` now returns `isToolCall: False` for
any non-`tools/call` method, and `handle()` passes those through as
`ALLOW` before ever reaching the danger-check logic. Regression-tested in
`tests/test_interceptor.py` against the real captured shape.

Still genuinely unverified: identity extraction (`gatewayRequest.context`)
was `null` on the one real event captured so far — but that was an
`initialize` call, which has no caller identity of its own by definition.
Whether `context.identity` gets populated for an authenticated `tools/call`
(and in what shape) hasn't been confirmed yet. Needs a real authenticated
`tools/call` to close out.

### The response shape was wrong, and a live test caught it (resolved)

The first fixed build of the interceptor got past the `initialize` crash
above, but the very next real invocation failed differently: the Gateway's
own vended logs recorded `"log": "Received invalid response from
interceptor"`. The response shape (`_gateway_response`, returning
`{"action": "ALLOW"|"DENY"}`) had been *invented* by inference, never
checked against AWS's actual interceptor contract. It was wrong.

The real contract, confirmed directly from AWS's docs
(`gateway-interceptors-types.html`, not guessed): a REQUEST interceptor has
no allow/deny verb at all. It must return one of:

- `mcp.transformedGatewayRequest.body` — the (optionally modified) JSON-RPC
  request body. Returning the original body unchanged is how you express
  ALLOW; the Gateway proceeds to call the target with that body.
- `mcp.transformedGatewayResponse` (`statusCode` + JSON-RPC `body`) — the
  Gateway responds with this immediately and never calls the target ("If
  the interceptor output contains a transformedGatewayResponse, the
  gateway will respond with that content immediately, even if
  transformedGatewayRequest is also provided."). This is how DENY has to
  be expressed: synthesize a JSON-RPC error response yourself, using the
  original request's `id`, since there's no native reject.

Both are wrapped in `{"interceptorOutputVersion": "1.0", "mcp": {...}}`.
Fixed in `interceptor/handler.py` as `_allow_response` / `_deny_response`,
replacing the old `_gateway_response`. Regression-tested in
`tests/test_interceptor.py`.

One caveat that's still a best-effort choice rather than a confirmed fact:
the JSON-RPC error `code` used for DENY (`-32001`, within the
implementation-defined server-error range per the JSON-RPC 2.0 spec).
AWS's docs show the ALLOW/pass-through shape worked end-to-end but don't
include a worked DENY/error example, so only the response *envelope* is
confirmed — the specific error code and how MCP clients are expected to
surface it to a calling agent is not.

There's also a CDK alpha module specifically for this —
`@aws-cdk/aws-bedrock-agentcore-alpha` — which reportedly supports
attaching a Lambda interceptor as a first-class construct with automatic
IAM permission grants. Not adopted here yet (alpha-versioned, and its exact
Python API wasn't verified before this was written), but worth evaluating
as a follow-up to fold Gateway + interceptor creation into
`infra/cdk/truclaw_stack.py` directly instead of the separate imperative
script, for the same reason everything else in this repo is CDK-managed
rather than click-ops or one-off CLI commands.

### Open follow-up: CUSTOM_JWT (Cognito) inbound auth rejects a token that matches its own configured scope

While testing Track A/B end-to-end, the Gateway's `CUSTOM_JWT` authorizer
consistently returned `403 insufficient_scope` for every access token
tried, including one that should unambiguously have satisfied the check:

1. A Cognito Resource Server was created with a custom scope
   (`truclaw/invoke`).
2. A dedicated M2M app client was created with `client_credentials` grant
   enabled and that scope allowed.
3. The Gateway's `authorizerConfiguration.customJWTAuthorizer.allowedScopes`
   was explicitly set to `["truclaw/invoke"]` (confirmed via
   `get-gateway`, and confirmed propagated via the Gateway's own
   `/.well-known/oauth-protected-resource` document showing
   `"scopes_supported": ["truclaw/invoke"]`).
4. A fresh access token was minted via the real OAuth `/oauth2/token`
   endpoint (`grant_type=client_credentials`), decoded and confirmed to
   carry `"token_use": "access"` and `"scope": "truclaw/invoke"` — an
   exact match against the Gateway's own `allowedScopes`.
5. That exact token, sent via raw `curl` directly to the Gateway's `/mcp`
   endpoint (ruling out any client-library involvement), still got
   `403` with `WWW-Authenticate: Bearer error="insufficient_scope",
   scope="truclaw/invoke", ...` — the challenge header demanding the exact
   scope the token already carried.

Every lever documented in AWS's own inbound-auth and JWT-authorizer pages
(`gateway-inbound-auth.html`, `inbound-jwt-authorizer.html`) was set up per
the documented contract. This is either a genuine AgentCore platform bug or
an unexplained interaction between Cognito's `client_credentials` token
issuance and the Gateway's scope-matching logic — not something
diagnosable from outside AWS's own systems. **Filed as an open item to
raise with AWS support**, with the full repro (resource server config,
token claims, exact curl request/response) preserved in this repo's
session history.

**Workaround used to unblock testing**: switched the Gateway's
`authorizerType` from `CUSTOM_JWT` to `AWS_IAM` for the Track A/B test run.
This only changes how the *test client* authenticates to the Gateway —
none of TruClaw's actual logic (the interceptor, `danger.py`'s
classification, the escalation state machine) sits upstream of or depends
on which inbound auth type the Gateway uses, so this doesn't compromise
what's being validated. Signing is done via AWS's own
`mcp-proxy-for-aws` package (`aws_iam_streamablehttp_client`, service name
`bedrock-agentcore`) rather than hand-rolled SigV4 — see
`testing/echo_tool/test_client_iam.py`. Trade-off, per AWS's own docs
on IAM vs. JWT+interceptor auth: `AWS_IAM` only supports
Gateway-level authorization (`bedrock-agentcore:InvokeGateway` on the whole
Gateway ARN), not tool-level access control per agent — for a production
multi-agent deployment where different agents should see different tool
sets, `CUSTOM_JWT` (once its scope bug is understood) or Cedar-based
per-tool policy remains the right long-term answer. `AWS_IAM` is being
used here purely as a testing workaround, not a proposed production
architecture change.

## What's deliberately not built yet

### Priority follow-up: no path to surface business-logic failures to the end user

Real gap, not a nice-to-have. Today, when something like "no paired device"
fails a request, it's visible in exactly two places: the S3 ledger
(admin-only, via `admin/cli.py`) and a `DENY` response with a free-text
`reason` string handed back through the Gateway to the *calling agent* —
not the customer. What the agent does with that string is undefined; a
customer has no realistic way to learn "you need to pair a device" from
either surface, and they should never be expected to be reading CloudWatch
logs to find out why an action silently failed.

Root cause: this repo ported the enforcement machinery from the original
implementation but not the user-facing pairing/onboarding flow
(`pair_route.py`, the "say *pair my TruClaw device*" conversational entry
point in `chat_handler.py`) — neither was ported, both were judged
FastAPI/Google-Chat-specific glue out of scope for the Gateway-interceptor
design. `truclaw_aws/pairing.py` still has the underlying
`start_pairing()`/`poll_for_pairing()` logic; nothing in this repo invokes
it or exposes it to an end user.

Two concrete pieces of work, not one:
1. Structure `DENY` responses with a machine-readable `reasonCode` (e.g.
   `NO_PAIRED_DEVICE`) instead of only a free-text `reason`, so a calling
   agent *can* build real UX around it — and document this as an explicit
   integration contract for agent authors.
2. Build or re-port an actual pairing-initiation flow, and make it
   proactive where possible (tell a user they need to pair *before* they
   hit a wall on a real dangerous action, not only reactively when one
   fails).

**Important constraint on any future design here, settled explicitly:**
whatever notification/approval surface gets built must stay strictly
out-of-band from the agent's own chat/UI channel. The security value of
the signed-device-approval mechanism comes entirely from being
independent of anything the agent (or content it ingests, e.g. a prompt
injection) can influence or render. Do not fold this into an in-chat
mechanism like AgentCore's AG-UI protocol, however convenient that might
look — collapsing the approval surface into the same channel as the
action being approved defeats the purpose of an independent check.

### Other follow-ups

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
- **Step Functions Catch/Denied inconsistency.** The standalone reference
  `statemachine/escalation.asl.json` has an explicit `Catch` → `Denied`
  state for a clean timeout output; the actual CDK-deployed construct in
  `infra/cdk/truclaw_stack.py` doesn't have the equivalent wired in.
  Harmless today because `interceptor/handler.py`'s poll loop
  independently treats any non-SUCCEEDED terminal execution status as a
  deny, but worth reconciling for consistency between the reference file
  and what's actually deployed.

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
