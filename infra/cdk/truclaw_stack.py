"""
CDK stack for the "classic" AWS resources: S3, Lambda, EventBridge. This
does NOT create the AgentCore Gateway, Runtime, or Identity resources --
CDK L2 support for AgentCore is not mature enough at the time of writing
to trust generated constructs for it, and getting the Gateway interceptor
wiring right matters more than saving a few manual steps. See
infra/scripts/setup_agentcore.sh for that half, using the `agentcore` CLI
(aws/bedrock-agentcore-starter-toolkit) instead.

*** No more Step Functions ***
This stack used to also provision a Step Functions STANDARD state machine
plus two extra Lambdas (SendChallengeFunction as its task, and
ResumeHandlerFunction behind a Function URL) for a task-token callback
pattern. That was built on an unverified assumption -- that the push
relay would call back into an AWS webhook when a device responded -- which
turned out to be wrong: the relay is poll-based (push a challenge, poll
for the result, same caller does both), confirmed by reading
truclaw_adk/challenge.py in full after two rounds of live relay 400s. Once
the escalation logic (now truclaw_aws/challenge.py) does that whole
push-then-poll cycle itself inside the interceptor's own Lambda
invocation, there's no unpredictable external caller left needing a
durable, resumable-by-anyone wait state -- the entire reason Step
Functions was there. Removed. See docs/ARCHITECTURE.md for the full story
and interceptor/handler.py's module docstring for the resulting design.

Deployment order: `cdk deploy` this stack first (it has no AgentCore
dependency), note the outputs (bucket name, interceptor Lambda ARN), then
run setup_agentcore.sh with those values to wire the Gateway interceptor
to the interceptor Lambda's ARN.
"""
import os

from aws_cdk import (
    Stack, Duration, CfnOutput, BundlingOptions, DockerImage,
    aws_s3 as s3,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
)
from constructs import Construct

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


class TruClawStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- S3 bucket: replaces the GCS bucket entirely (policies, ledger
        # shards, memory.md, usage_summary.json, device pairing records) ---
        bucket = s3.Bucket(
            self, "TruClawBucket",
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="expire-old-ledger-shards",
                    prefix="truclaw/policies/",
                    expiration=Duration.days(400),  # audit retention; tune per compliance need
                )
            ],
        )

        # All Lambdas share one asset: the whole repo, with third-party deps
        # pip-installed into the asset at build time. boto3 ships with the
        # Lambda runtime already; httpx, cryptography, and google-genai do
        # not, hence the bundling step below.
        code_asset = lambda_.Code.from_asset(
            REPO_ROOT,
            bundling=BundlingOptions(
                image=DockerImage.from_registry("public.ecr.aws/sam/build-python3.12"),
                command=[
                    "bash", "-c",
                    "pip install -r requirements.txt -t /asset-output && "
                    "cp -au truclaw_aws interceptor aggregator admin /asset-output/",
                ],
            ),
        )
        # escalation/ deliberately excluded -- both its Lambdas
        # (send_challenge.py, resume_handler.py) are superseded by
        # truclaw_aws/challenge.py, called directly from interceptor_fn.
        # See this file's module docstring.

        # NOTE: AWS_REGION is deliberately not set here -- Lambda's runtime
        # injects it automatically, and CDK/CloudFormation will reject an
        # explicit attempt to set it as a reserved environment variable.
        # truclaw_aws/config.py reads it via os.getenv("AWS_REGION", ...)
        # and will pick up the runtime-provided value with no extra wiring.
        common_env = {
            "TRUCLAW_S3_BUCKET": bucket.bucket_name,
        }

        # --- Secrets / operator-supplied config, read from the deployer's
        # shell environment at `cdk deploy` time. These are NOT defaulted --
        # missing either one means the interceptor fails closed on every
        # dangerous call (no classifier key) or no push ever gets sent (no
        # relay URL), so fail the synth loudly instead of deploying
        # something silently broken.
        #
        # Plain Lambda environment variables are a pragmatic V1 choice, not
        # the final answer for a real secret -- moving GOOGLE_API_KEY into
        # AWS Secrets Manager (with the interceptor reading it at cold start
        # instead of from os.environ) is a reasonable hardening step once
        # this is past pilot stage. Not done here to keep this deploy path
        # simple to reason about.
        google_api_key = os.environ.get("GOOGLE_API_KEY")
        relay_url = os.environ.get("TRUKYC_RELAY_URL")
        if not google_api_key:
            raise ValueError(
                "GOOGLE_API_KEY must be set in your shell before `cdk deploy` -- "
                "the interceptor's risk classifier needs it."
            )
        if not relay_url:
            raise ValueError(
                "TRUKYC_RELAY_URL must be set in your shell before `cdk deploy` -- "
                "this is your push-notification relay's base URL."
            )

        # Optional knobs -- these already have sane defaults in
        # truclaw_aws/config.py, only pass them through if the deployer
        # wants to override the default.
        optional_env = {
            k: os.environ[k]
            for k in (
                "TRUCLAW_CLASSIFIER_MODEL",
                "TRUCLAW_ENFORCE",
                "TRUCLAW_CHALLENGE_TIMEOUT_SECONDS",
            )
            if k in os.environ
        }

        # --- Interceptor Lambda: the actual before-tool-call hook ---
        # timeout=180s: needs headroom over TRUCLAW_CHALLENGE_TIMEOUT_SECONDS
        # (120s default), since this single Lambda invocation now does the
        # entire escalation push-then-poll cycle itself (truclaw_aws/
        # challenge.py, called directly from interceptor/handler.py) rather
        # than handing off to separate infrastructure. See this file's and
        # interceptor/handler.py's module docstrings for why that's now the
        # design, instead of Step Functions.
        interceptor_fn = lambda_.Function(
            self, "InterceptorFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="interceptor.handler.handle",
            code=code_asset,
            timeout=Duration.seconds(180),
            memory_size=256,
            environment={
                **common_env, **optional_env,
                "GOOGLE_API_KEY": google_api_key,
                "TRUKYC_RELAY_URL": relay_url,
            },
        )

        # --- aggregator Lambda, on an hourly EventBridge schedule ---
        aggregator_fn = lambda_.Function(
            self, "AggregatorFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="aggregator.handler.handle",
            code=code_asset,
            timeout=Duration.minutes(5),
            memory_size=256,
            environment=common_env,
        )
        events.Rule(
            self, "AggregatorSchedule",
            schedule=events.Schedule.rate(Duration.hours(1)),
            targets=[targets.LambdaFunction(aggregator_fn)],
        )

        for fn in (interceptor_fn, aggregator_fn):
            bucket.grant_read_write(fn)

        CfnOutput(self, "BucketName", value=bucket.bucket_name)
        CfnOutput(self, "InterceptorFunctionArn", value=interceptor_fn.function_arn)
