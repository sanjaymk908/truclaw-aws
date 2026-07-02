#!/usr/bin/env bash
# Deploys the throwaway echo test tool as a standalone Lambda -- NOT via
# CDK, deliberately, since this is disposable test infrastructure, not
# part of the product. Safe to delete (`aws lambda delete-function
# --function-name truclaw-echo-tool`) once Track A/B testing is done.

set -euo pipefail

: "${AWS_REGION:?e.g. us-east-1}"
: "${AWS_ACCOUNT_ID:?your 12-digit account id, from aws sts get-caller-identity}"

ROLE_NAME="truclaw-echo-tool-role"
FUNCTION_NAME="truclaw-echo-tool"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "1. Create a minimal execution role (basic logging only) if it doesn't exist..."
if ! aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document '{
      "Version": "2012-10-17",
      "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    }'
  aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  echo "   Created $ROLE_NAME -- waiting a few seconds for IAM propagation..."
  sleep 10
else
  echo "   $ROLE_NAME already exists, reusing it."
fi

echo "2. Zip and deploy the function..."
cd "$HERE"
rm -f function.zip
zip -q function.zip handler.py
if aws lambda get-function --function-name "$FUNCTION_NAME" --region "$AWS_REGION" >/dev/null 2>&1; then
  aws lambda update-function-code \
    --function-name "$FUNCTION_NAME" \
    --zip-file fileb://function.zip \
    --region "$AWS_REGION"
else
  aws lambda create-function \
    --function-name "$FUNCTION_NAME" \
    --runtime python3.12 \
    --role "arn:aws:iam::${AWS_ACCOUNT_ID}:role/${ROLE_NAME}" \
    --handler handler.handler \
    --zip-file fileb://function.zip \
    --region "$AWS_REGION"
fi
rm -f function.zip

echo
echo "Done. Function ARN:"
aws lambda get-function --function-name "$FUNCTION_NAME" --region "$AWS_REGION" \
  --query "Configuration.FunctionArn" --output text
