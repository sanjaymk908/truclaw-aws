#!/usr/bin/env bash
# AgentCore setup — the half of the deployment CDK deliberately does NOT do.
#
# *** These commands are illustrative, not verified against a live account. ***
# AgentCore (Runtime/Gateway/Identity/Policy) is a fast-moving, recently-GA'd
# service. Rather than fabricate exact CDK L2 constructs or boto3 call shapes
# for it and risk shipping something subtly wrong, this script documents the
# steps conceptually using the `agentcore` CLI from
# https://github.com/aws/bedrock-agentcore-starter-toolkit (or the newer
# https://github.com/aws/agentcore-cli for new projects, per that repo's own
# migration note) and the AWS CLI directly. Run `agentcore --help` and
# `aws bedrock-agentcore-control help` yourself and reconcile flag names
# before actually running this against your account.
#
# Run infra/cdk (`cdk deploy`) FIRST and capture its outputs -- this script
# needs the interceptor Lambda ARN, the S3 bucket name, and the resume
# handler Function URL from that stack.

set -euo pipefail

: "${INTERCEPTOR_LAMBDA_ARN:?set to the CDK stack's InterceptorFunctionArn output}"
: "${TRUCLAW_S3_BUCKET:?set to the CDK stack's BucketName output}"
: "${AWS_REGION:?e.g. us-east-1}"

echo "1. Install the starter toolkit CLI (verify current package name):"
echo "   pip install bedrock-agentcore-starter-toolkit"
echo

echo "2. Create (or reuse) an AgentCore Gateway:"
echo "   agentcore gateway create --name truclaw-gateway --region \$AWS_REGION"
echo "   # Note the returned Gateway ID/ARN."
echo

echo "3. Register your agent's tools as Gateway targets."
echo "   Every tool a TruClaw-protected agent calls MUST be registered here --"
echo "   this interceptor never sees a tool call that bypasses the Gateway."
echo "   agentcore gateway add-target --gateway-id <id> --openapi-spec <path-or-url>"
echo "   # repeat per tool/target, or per OpenAPI spec covering multiple tools"
echo

echo "4. Attach the REQUEST interceptor to the Gateway, pointed at the"
echo "   interceptor Lambda deployed by CDK:"
echo "   agentcore gateway add-interceptor --gateway-id <id> \\"
echo "     --type REQUEST --lambda-arn \$INTERCEPTOR_LAMBDA_ARN"
echo

echo "5. Configure AgentCore Identity for inbound (who is calling the agent)"
echo "   and outbound (Gateway -> your banking APIs) auth. Reuse an existing"
echo "   OAuth IdP (Cognito, Auth0, Keycloak) if you have one -- Identity is"
echo "   free when used through Runtime/Gateway, so there is no cost reason"
echo "   to avoid wiring it fully:"
echo "   agentcore identity configure --gateway-id <id> --idp-issuer <issuer-url>"
echo

echo "6. Deploy the agent itself onto AgentCore Runtime, pointed at the new"
echo "   Gateway for tools instead of local in-process tools:"
echo "   agentcore runtime deploy --agent-dir <path-to-your-adk-agent> \\"
echo "     --gateway-id <id>"
echo

echo "7. Turn on Observability so traces exist before you need them:"
echo "   agentcore observability enable --gateway-id <id> --runtime-id <id>"
echo

echo "8. Give the relay (device push service) the resume handler's Function"
echo "   URL from the CDK stack output as its callback target for the"
echo "   /verify-callback path used in escalation/send_challenge.py."
echo
echo "Re-run this checklist against 'agentcore --help' output before using it --"
echo "flag names above are best-effort as of when this port was written."
