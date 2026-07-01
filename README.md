# truclaw-aws

AWS/AgentCore port of [TruClaw](https://github.com/sanjaymk908/trukyc-adk) (mirrored
locally as `truclaw_adk`). This is not a lift-and-shift of the Google ADK
implementation — the enforcement point moves from an in-process ADK
callback to an **AgentCore Gateway REQUEST interceptor**, so the hook works
regardless of which framework a given agent was built on (ADK, LangGraph,
Strands, CrewAI, ...). That's the difference between "our agent has
guardrails" and "TruClaw governs the fleet," which matters for the Fiserv
agentOS / AgentCore partnership angle this port exists for.

## Architecture

```
Tool call
   │
   ▼
AgentCore Gateway ── REQUEST interceptor ──▶ interceptor/handler.py
                                                  │
                                     danger.check_danger() (unchanged rubric)
                                                  │
                              ┌───────────────────┼───────────────────┐
                              ▼                   ▼                   ▼
                            ALLOW               DENY              ESCALATE
                         (fast path)         (fast path)              │
                                                                       ▼
                                                     Step Functions Express Sync
                                                     (statemachine/escalation.asl.json)
                                                                       │
                                                          escalation/send_challenge.py
                                                            (push to paired device)
                                                                       │
                                                          device responds, signed JWT
                                                                       │
                                                          escalation/resume_handler.py
                                                        (verifies JWT, SendTaskSuccess)
                                                                       │
                                                     workflow resolves, interceptor
                                                        returns ALLOW/DENY
```

The fast path (ALLOW/DENY) never touches Step Functions and stays cheap and
synchronous — that's the overwhelming majority of tool calls. Only the
ESCALATE path pays for a workflow execution, and even that stays bounded
(Express Sync, capped around 5 minutes) rather than the in-process
`asyncio` + polling-thread + module-level dict that `truclaw_adk/challenge.py`
used. See `interceptor/handler.py`'s docstring for why that design is
appropriate for today's ~120s challenge timeout, and what would need to
change if that timeout ever grows materially (on-call/escalation-chain
routing, discussed as V1 follow-up, not built here).

## Module map back to `truclaw_adk`

| truclaw_adk file | truclaw-aws equivalent | Changed? |
|---|---|---|
| `config.py` | `truclaw_aws/config.py` | S3 bucket instead of GCS bucket; adds `ESCALATION_STATE_MACHINE_ARN` |
| `gcs_storage.py` | `truclaw_aws/s3_storage.py` | GCS → S3; adds put/get/list-bytes helpers used by the new per-object storage |
| `jwt_verify.py` | `truclaw_aws/jwt_verify.py` | Unchanged logic (pure crypto) |
| `pairing.py` | `truclaw_aws/pairing.py` | **Redesigned**: one S3 object per paired device instead of one shared blob — removes a read-modify-write race, see file docstring |
| `ledger.py` | `truclaw_aws/ledger.py` | **Redesigned**: one immutable S3 object per event instead of re-uploading a growing shared blob on every write — removes a real data-loss bug under concurrent writers, see file docstring |
| `policy.py` | `truclaw_aws/policy.py` | Same single-object-per-agent shape (policy edits are human-gated and infrequent, so no race to fix here) |
| `danger.py` | `truclaw_aws/danger.py` | Same rubric and Gemini call; Bedrock model swap left as an unwired V2 stub |
| `guardrail.py` + `protect.py` + `autopatch.py` | `interceptor/handler.py` | **Re-homed**: from an ADK in-process monkeypatch to an AgentCore Gateway interceptor |
| `challenge.py` | `escalation/send_challenge.py` + `escalation/resume_handler.py` + `statemachine/escalation.asl.json` | **Re-homed**: from in-process polling to a Step Functions callback (`waitForTaskToken`) |
| `cron_aggregator.py` (Cloud Run Job) | `aggregator/handler.py` (EventBridge-scheduled Lambda) | Same aggregation logic, reads the new per-event ledger objects |
| `admin_cli.py` | `admin/cli.py` | Same commands, S3-backed |
| `chat_handler.py`, `pair_route.py`, `cli.py` | *(not ported)* | FastAPI/Google-Chat-specific glue; out of scope for the Gateway-interceptor design — revisit if a chat surface is still needed on AWS |

## Design notes vs. `truclaw_adk`

Two deliberate improvements, not scope creep — both replace a shared,
overwritten S3/GCS object with one-object-per-item, which is *less* code
than the original read-modify-write pattern, not more:

- **Ledger**: every tool-call decision becomes its own immutable,
  timestamp-prefixed S3 object (`truclaw/policies/<agentId>/ledger/yyyy/mm/dd/...`)
  instead of the whole ledger file being re-uploaded (overwriting the shared
  blob) on every single event. That was a real bug in `truclaw_adk`: under
  concurrent writers, whichever process uploaded last silently dropped the
  others' events from the canonical copy.
- **Pairing**: every paired device becomes its own S3 object
  (`truclaw/pairing/<userId>/<publicKeyHash>.json`) instead of one shared
  `paired.json` blob mutated on every pairing event.

`memory.md` and `usage_summary.json` keep the original single-object shape
— they have exactly one writer (the aggregator Lambda), so there's nothing
to race.

## What's NOT solved here (deliberately, per "don't overdesign yet")

- **Cedar policy migration.** AgentCore Policy uses Cedar; this port keeps
  the original flat JSON policy shape (`safeTools`/`alwaysDangerousTools`/`toolThresholds`)
  evaluated inside the interceptor Lambda. Migrating to native Cedar policies
  is a real hardening step for a bank-facing product but isn't required to
  get the interceptor placement + async escalation working.
- **On-call routing / escalation chains.** `escalation/send_challenge.py`
  still just pushes to the account owner's paired device(s), same persona
  as `truclaw_adk`. The seam for swapping this to an ops/compliance on-call
  queue is that this function is the only thing that needs to change — the
  state machine and interceptor don't know or care what "ask a human" means
  underneath.
- **Bedrock-hosted classifier model.** `danger.py` keeps calling Gemini
  directly, exactly like `truclaw_adk`. `_bedrock_generate` is a stub, not
  wired in, and not exercised against a live endpoint.

## Known open question before production

AgentCore Gateway interceptors are a new (2026) capability. The exact
request/response JSON schema for a REQUEST interceptor is not fully
stabilized in public docs at the time this was written —
`interceptor/handler.py`'s `_parse_gateway_event` and `_gateway_response`
are written against the documented *concept*, not a verified field-for-field
schema. Confirm against the current "Using interceptors with Gateway" AWS
docs before pointing a real Gateway at this. The decision logic in between
(the actual hook design) does not need to change regardless of how those
two functions end up being adjusted.

## Deploying

1. `cd infra/cdk && pip install -r requirements.txt && cdk bootstrap && cdk deploy`
   — creates the S3 bucket, all four Lambdas, the Step Functions state
   machine, and the aggregator's hourly EventBridge schedule. Note the
   stack outputs (bucket name, interceptor Lambda ARN, resume handler
   Function URL).
2. Run `infra/scripts/setup_agentcore.sh` (after exporting the env vars it
   checks for) to create the AgentCore Gateway, register your agent's tools
   as Gateway targets, attach the interceptor Lambda, configure Identity,
   and deploy the agent itself onto AgentCore Runtime. That script documents
   commands using the `agentcore` CLI — verify flags against
   `agentcore --help` for your installed version before running, since this
   is the fastest-moving part of the stack.
3. Point your device-push relay's callback at the resume handler's Function
   URL for the `/verify-callback` path.
4. Seed each agent's policy: copy `policies/TruClaw-Policies.template.json`
   to `s3://<bucket>/truclaw/policies/<agentId>/TruClaw-Policies.json` (or
   let it auto-bootstrap on first call and edit the result — same as
   `truclaw_adk`), replacing `safeTools`/`alwaysDangerousTools`/`businessRules`
   for your domain.

## Cost (rough, pilot-scale)

Pulled from AWS's published AgentCore pricing (verify current rates before
committing): Gateway is $0.005 per 1,000 tool invocations, Policy
authorization is $0.000025 per request, Identity is free when used through
Runtime/Gateway, and Runtime is $0.0895/vCPU-hour + $0.00945/GB-hour billed
per second with no CPU charge during I/O wait. Step Functions Express and
Lambda both have meaningful always-free tiers that comfortably cover a
pilot's volume. At pilot scale (order 10,000 tool calls/month) this is a
single-digit-to-$20/month bill, dominated by CloudWatch log volume and
whatever LLM the classifier calls — not by any AgentCore-specific line
item. Re-estimate once you have a real Fiserv-fleet call-volume number;
every component here is linear and cheap per unit.

## Tests

```
pip install -r requirements.txt
pytest tests/
```

Unit tests cover the threshold/policy logic and the classifier
JSON-extraction helpers without touching AWS or calling a live model. There
is deliberately no integration test hitting a real Gateway/Runtime/Step
Functions setup in this repo yet — add one once the open question above is
resolved against a real account.
