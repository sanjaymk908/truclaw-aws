#!/usr/bin/env bash
# AgentCore setup — the half of the deployment CDK deliberately does NOT do.
#
# Run infra/cdk (`cdk deploy`) FIRST and capture its outputs -- this script
# needs the interceptor Lambda ARN, the S3 bucket name, and the resume
# handler Function URL from that stack.
#
# Steps 1-4 below are verified against AWS's own docs and a live CLI
# session, not guessed -- see docs/ARCHITECTURE.md for how that was
# confirmed (it took three wrong turns: a deprecated starter-toolkit CLI
# with no interceptor support at all, the newer @aws/agentcore CLI which
# also doesn't support interceptor config yet, and finally AWS's own docs
# confirming that's expected -- interceptor configuration is a parameter
# on create-gateway/update-gateway itself, not a separate CLI command in
# either tool). Steps 5-7 are still best-effort -- re-check
# `agentcore identity --help` / `agentcore add --help` output against your
# installed version before running them, same as we did for 1-4.

set -euo pipefail

: "${INTERCEPTOR_LAMBDA_ARN:?set to the CDK stack's InterceptorFunctionArn output}"
: "${TRUCLAW_S3_BUCKET:?set to the CDK stack's BucketName output}"
: "${AWS_REGION:?e.g. us-east-1}"

echo "1. Install the current AgentCore CLI (the older bedrock-agentcore-starter-toolkit"
echo "   is deprecated and does not receive new features):"
echo "   npm install -g @aws/agentcore"
echo

echo "2. Create the Gateway and its IAM role/auth config using the AgentCore CLI --"
echo "   this part it does support well. Adjust --authorizer-type and the JWT"
echo "   discovery/audience values to your actual identity provider (Cognito,"
echo "   Auth0, Keycloak, etc.):"
echo "   agentcore add gateway \\"
echo "     --name truclaw-gateway \\"
echo "     --protocol-type MCP \\"
echo "     --authorizer-type CUSTOM_JWT \\"
echo "     --discovery-url <your-oidc-discovery-url> \\"
echo "     --allowed-audience <your-audience>"
echo "   agentcore deploy"
echo "   # Note the resulting Gateway ID/ARN from the deploy output."
echo

echo "3. Register your agent's tools as Gateway targets. Every tool a"
echo "   TruClaw-protected agent calls MUST be registered here -- this"
echo "   interceptor never sees a tool call that bypasses the Gateway."
echo "   For a Lambda-backed tool:"
echo "     agentcore add gateway-target --gateway <name> --type lambda-function-arn \\"
echo "       --lambda-arn <tool-lambda-arn> --tool-schema-file <path-to-schema.json>"
echo "   For tools behind an OpenAPI spec, MCP server, or AgentCore Runtime,"
echo "   see 'agentcore add gateway-target --help' for the matching --type."
echo "   agentcore deploy"
echo

echo "4. Attach the REQUEST interceptor to the Gateway. This is NOT supported"
echo "   by the agentcore CLI as of this writing (confirmed against AWS's own"
echo "   docs, not assumed) -- interceptorConfigurations is a parameter on the"
echo "   raw create-gateway/update-gateway API. Find your gateway identifier first:"
echo "   aws bedrock-agentcore-control list-gateways --region \$AWS_REGION"
echo "   # Then, using the id/arn from that output (confirm the exact flag name"
echo "   # against 'aws bedrock-agentcore-control update-gateway help' for your"
echo "   # installed CLI version before running):"
echo "   aws bedrock-agentcore-control update-gateway \\"
echo "     --gateway-identifier <gateway-id-from-above> \\"
echo "     --region \$AWS_REGION \\"
echo "     --interceptor-configurations '[{"
echo "         \"interceptor\": {\"lambda\": {\"arn\": \"'\"\$INTERCEPTOR_LAMBDA_ARN\"'\"}},"
echo "         \"interceptionPoints\": [\"REQUEST\"],"
echo "         \"inputConfiguration\": {\"passRequestHeaders\": false}"
echo "     }]'"
echo "   # passRequestHeaders is false here deliberately -- interceptor/handler.py"
echo "   # doesn't need raw headers today, and AWS's own docs warn they can carry"
echo "   # auth tokens/credentials. Only set true if you have a specific need,"
echo "   # e.g. reading a JWT the Gateway itself didn't already validate."
echo

echo "5. Configure AgentCore Identity for inbound (who is calling the agent)"
echo "   and outbound (Gateway -> your banking APIs) auth. Not re-verified with"
echo "   the same rigor as steps 1-4 -- check 'agentcore identity --help' for"
echo "   your installed version first:"
echo "   agentcore add credential --type oauth ..."
echo "   # or: agentcore identity create-workload-identity ..."
echo

echo "6. Deploy the agent itself onto AgentCore Runtime, pointed at the new"
echo "   Gateway for tools instead of local in-process tools. Not re-verified --"
echo "   check 'agentcore configure --help' and 'agentcore create --help' first,"
echo "   both confirmed to exist and support --framework GoogleADK:"
echo "   agentcore create --framework GoogleADK --type create ..."
echo "   agentcore deploy"
echo

echo "7. Give the relay (device push service) the resume handler's Function"
echo "   URL from the CDK stack output as its callback target for the"
echo "   /verify-callback path used in escalation/send_challenge.py."
echo
echo "Steps 5-6 are the remaining unverified parts of this script -- confirm"
echo "against your installed 'agentcore --help' output before running, same"
echo "approach that caught the wrong assumptions in steps 1-4."
