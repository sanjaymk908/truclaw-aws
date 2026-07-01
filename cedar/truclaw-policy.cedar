// Cedar translation of policies/TruClaw-Policies.template.json.
//
// *** SUPERSEDED BY docs/ARCHITECTURE.md's "Cedar / AgentCore Policy" section. ***
// This file was a feasibility sketch showing that toolThresholds and
// alwaysDangerousTools *can* be expressed in Cedar via a context.humanApproved
// workaround -- not that they *should* be. The current direction keeps all
// risk-tiering logic in truclaw_aws/danger.py + policy.py unchanged, and
// reserves Cedar for a separate, smaller set of static authorization facts
// (not built yet). Read this file as "here's how the mapping works," not
// as the intended production policy set.
//
// This covers exactly the three deterministic tiers Cedar can express --
// safeTools, alwaysDangerousTools, toolThresholds. `businessRules` (the
// template's free-text field) has NO Cedar equivalent and is not
// translated below -- it stays exactly where it is today, as prompt
// context handed to the Gemini classifier in truclaw_aws/danger.py for any
// tool call that falls through every policy statement here ("unclassified"
// in the JSON).
//
// *** ILLUSTRATIVE -- confirm exact resource/action shape against live
// AgentCore Policy docs before deploying. ***

// === safeTools -> unconditional permit, one clause, mirrors the JSON array ===
permit(
  principal,
  action == Action::"InvokeTool",
  resource
) when {
  resource.toolName in [
    "read", "session_status", "list", "ls", "web_search", "web_fetch",
    "browser_snapshot", "status", "truclaw_pair", "truclaw_status",
    "transfer_to_agent", "transfer_to_agent_tool", "agent_transfer",
    "load_artifacts", "list_artifacts", "save_artifacts"
  ]
};

// === alwaysDangerousTools -> forbid unless already human-approved ===
//
// Important: this "forbid" is the ESCALATE signal, not a hard rejection.
// interceptor/handler.py treats a Policy DENY that matches one of these
// specific tools as "start the Step Functions escalation flow"
// (statemachine/escalation.asl.json), not as final. context.humanApproved
// only becomes true after escalation/resume_handler.py has already
// verified a signed device approval for this exact call -- Policy never
// computes that flag itself, it's a one-way input the interceptor supplies
// once it already knows the answer. In practice this means the interceptor
// doesn't need to re-call Policy after approval at all; it can just
// proceed and log, having already gotten the "yes, this needed approval"
// signal from the first Policy evaluation. Re-checking with
// humanApproved=true is only useful if you want Policy itself in the
// audit trail for the post-approval call too.
forbid(
  principal,
  action == Action::"InvokeTool",
  resource
) unless {
  context.humanApproved == true
} when {
  resource.toolName in [
    "place_trade", "execute_trade", "send_email",
    "send_email_via_porteden", "delete_email", "forward_email", "reply_email"
  ]
};

// === toolThresholds -> illustrative, since the template ships with {} ===
//
// The template has no populated threshold yet -- there's nothing to
// translate until an agent's policy actually sets one. Here's what it
// looks like once one exists, e.g. if TruClaw-Policies.json for a given
// agentId contained:
//
//   "toolThresholds": {
//     "wire_transfer": { "field": "amount", "safeBelow": 1000, "dailyLimit": 5 }
//   }
//
// Two statements fall out of it -- a permit for the safe case, a
// forbid/escalate for both the single-call and cumulative violation cases,
// exactly matching truclaw_aws/policy.py:check_threshold()'s three-way
// SAFE_BYPASS / violation / no-rule return today:

permit(
  principal,
  action == Action::"InvokeTool",
  resource
) when {
  resource.toolName == "wire_transfer" &&
  context.amount <= 1000
};

forbid(
  principal,
  action == Action::"InvokeTool",
  resource
) unless {
  context.humanApproved == true
} when {
  resource.toolName == "wire_transfer" &&
  (context.amount > 1000 || context.dailyCount >= 5)
};
