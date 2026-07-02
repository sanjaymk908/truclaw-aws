# Track A/B smoke test — throwaway, not part of the product

Proves the pipeline works end to end (Gateway -> interceptor -> tool, and
Gateway -> interceptor -> escalation -> approval) before a real agent or
real banking APIs are involved. Delete everything in this directory's
deployed resources once done (see bottom).

## 1. Deploy the echo Lambda

```
cd testing/echo_tool
export AWS_REGION=us-east-1
export AWS_ACCOUNT_ID=<your 12-digit account id>
./deploy.sh
```
Note the printed function ARN.

## 2. Register it as two Gateway targets

Once, as a safe-path tool (name "read", already in default safeTools —
should ALLOW immediately, no escalation):
```
agentcore add gateway-target \
  --gateway truclaw-gateway \
  --name echo-safe \
  --type lambda-function-arn \
  --lambda-arn <function ARN from step 1> \
  --tool-schema-file tool_schema_safe.json
```

Again, as a dangerous-path tool (name "send_email", already in default
alwaysDangerousTools — should trigger escalation):
```
agentcore add gateway-target \
  --gateway truclaw-gateway \
  --name echo-dangerous \
  --type lambda-function-arn \
  --lambda-arn <function ARN from step 1> \
  --tool-schema-file tool_schema_dangerous.json
agentcore deploy
```

If `--tool-schema-file`'s expected JSON shape doesn't match what's in
tool_schema_safe.json/tool_schema_dangerous.json, the error message should
name the field it actually wants -- adjust those two files directly, they're
disposable test artifacts.

## 3. Get a test JWT from Cognito

The app client needs USER_PASSWORD_AUTH enabled (probably isn't, by
default):
```
aws cognito-idp update-user-pool-client \
  --user-pool-id us-east-1_J2t5PolQS \
  --client-id 38gnegit99f4lupg279o0ocgls \
  --explicit-auth-flows ALLOW_ADMIN_USER_PASSWORD_AUTH ALLOW_REFRESH_TOKEN_AUTH \
  --region us-east-1
```

Create a test user and set a permanent password:
```
aws cognito-idp admin-create-user \
  --user-pool-id us-east-1_J2t5PolQS \
  --username truclaw-test-user \
  --message-action SUPPRESS \
  --region us-east-1

aws cognito-idp admin-set-user-password \
  --user-pool-id us-east-1_J2t5PolQS \
  --username truclaw-test-user \
  --password "<a real password meeting the pool's policy>" \
  --permanent \
  --region us-east-1
```

Get a token:
```
aws cognito-idp admin-initiate-auth \
  --user-pool-id us-east-1_J2t5PolQS \
  --client-id 38gnegit99f4lupg279o0ocgls \
  --auth-flow ADMIN_USER_PASSWORD_AUTH \
  --auth-parameters USERNAME=truclaw-test-user,PASSWORD="<same password>" \
  --region us-east-1
```
Grab `AuthenticationResult.IdToken` (or `AccessToken` -- try IdToken first,
since our authorizer's `allowedAudience` matches an ID token's `aud` claim
more directly than an access token's).

## 4. Call the Gateway (unverified request shape -- MCP is JSON-RPC 2.0,
this follows the standard `tools/call` method, but hasn't been confirmed
against AgentCore's specific implementation)

```
curl -s https://truclawgw-truclaw-gateway-yrcmlcuphn.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp \
  -H "Authorization: Bearer <token from step 3>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{"message":"track A test"}}}'
```

Repeat with `"name":"send_email"` for Track B -- this one should hang
(waiting on approval) rather than return immediately, since it should be
escalating through Step Functions and pushing to your relay.

## 5. Check what actually happened

Interceptor's raw event + decision:
```
aws logs tail /aws/lambda/TruClawAwsStack-InterceptorFunction57BF837B-85VCVzBQ8kQG --since 5m --region us-east-1
```

Ledger (check both `test-agent` and `unknown` -- see earlier discussion on
why the agentId extraction is still unverified):
```
python3 -m admin.cli view-ledger --agent-id test-agent --limit 20
python3 -m admin.cli view-ledger --agent-id unknown --limit 20
```

## Cleanup once done testing

```
agentcore remove gateway-target --gateway truclaw-gateway --name echo-safe
agentcore remove gateway-target --gateway truclaw-gateway --name echo-dangerous
agentcore deploy
aws lambda delete-function --function-name truclaw-echo-tool --region us-east-1
aws iam detach-role-policy --role-name truclaw-echo-tool-role --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam delete-role --role-name truclaw-echo-tool-role
```
