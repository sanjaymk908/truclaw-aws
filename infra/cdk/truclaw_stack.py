"""
CDK stack for the "classic" AWS resources: S3, Lambda, Step Functions, IAM,
EventBridge. This does NOT create the AgentCore Gateway, Runtime, or
Identity resources -- CDK L2 support for AgentCore is not mature enough at
the time of writing to trust generated constructs for it, and getting the
Gateway interceptor wiring right matters more than saving a few manual
steps. See infra/scripts/setup_agentcore.sh for that half, using the
`agentcore` CLI (aws/bedrock-agentcore-starter-toolkit) instead.

Deployment order: `cdk deploy` this stack first (it has no AgentCore
dependency), note the outputs (bucket name, Lambda ARNs, state machine ARN,
resume handler Function URL), then run setup_agentcore.sh with those values
to wire the Gateway interceptor to the interceptor Lambda's ARN.
"""
import os

from aws_cdk import (
    Stack, Duration, CfnOutput, BundlingOptions, DockerImage,
    aws_s3 as s3,
    aws_lambda as lambda_,
    aws_iam as iam,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as tasks,
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
                    "cp -au truclaw_aws interceptor escalation aggregator admin /asset-output/",
                ],
            ),
        )

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
        interceptor_fn = lambda_.Function(
            self, "InterceptorFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="interceptor.handler.handle",
            code=code_asset,
            # Needs headroom over CHALLENGE_TIMEOUT_SECONDS (120s default) since
            # _escalate() polls DescribeExecution rather than blocking on a
            # single synchronous call -- see interceptor/handler.py.
            timeout=Duration.seconds(180),
            memory_size=256,
            environment={**common_env, **optional_env, "GOOGLE_API_KEY": google_api_key},
        )

        # --- send_challenge Task Lambda (invoked by the state machine) ---
        send_challenge_fn = lambda_.Function(
            self, "SendChallengeFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="escalation.send_challenge.handle",
            code=code_asset,
            timeout=Duration.seconds(30),
            memory_size=128,
            environment={**common_env, "TRUKYC_RELAY_URL": relay_url},
        )

        # --- resume_handler Lambda, fronted by a Function URL the relay calls ---
        resume_fn = lambda_.Function(
            self, "ResumeHandlerFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="escalation.resume_handler.handle",
            code=code_asset,
            timeout=Duration.seconds(15),
            memory_size=128,
            environment=common_env,
        )
        resume_url = resume_fn.add_function_url(
            auth_type=lambda_.FunctionUrlAuthType.NONE,  # the JWT in the body is the auth
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

        for fn in (interceptor_fn, send_challenge_fn, resume_fn, aggregator_fn):
            bucket.grant_read_write(fn)

        # --- Step Functions state machine (escalation workflow) ---
        #
        # STANDARD, not Express: Express workflows (including Express Sync)
        # do not support the .waitForTaskToken integration pattern at all --
        # confirmed the hard way, via a CREATE_FAILED deploy
        # (SCHEMA_VALIDATION_FAILED) rather than caught in review. Standard
        # is the only state machine type that supports pausing on a task
        # token, which is the whole mechanism the escalation flow depends
        # on. The tradeoff: Standard has no StartSyncExecution API, so the
        # interceptor Lambda can't block on a single synchronous call the
        # way Express Sync would have let it -- it starts the execution
        # async and polls DescribeExecution in a short bounded loop instead
        # (see interceptor/handler.py:_escalate). Still synchronous from the
        # Gateway's point of view, still bounded by the same timeout -- just
        # polling Step Functions' own durable execution state rather than
        # blocking on an API that turned out not to exist for this pattern.
        send_challenge_task = tasks.LambdaInvoke(
            self, "SendChallengeTask",
            lambda_function=send_challenge_fn,
            integration_pattern=sfn.IntegrationPattern.WAIT_FOR_TASK_TOKEN,
            payload=sfn.TaskInput.from_object({
                "Token": sfn.JsonPath.task_token,
                "payload": sfn.JsonPath.entire_payload,
            }),
            task_timeout=sfn.Timeout.duration(Duration.seconds(150)),
        )

        state_machine = sfn.StateMachine(
            self, "EscalationStateMachine",
            state_machine_type=sfn.StateMachineType.STANDARD,
            definition_body=sfn.DefinitionBody.from_chainable(send_challenge_task),
            timeout=Duration.minutes(4),
        )

        interceptor_fn.add_environment(
            "TRUCLAW_ESCALATION_STATE_MACHINE_ARN", state_machine.state_machine_arn
        )
        state_machine.grant_start_execution(interceptor_fn)
        state_machine.grant_task_response(resume_fn)
        # grant_start_execution doesn't cover DescribeExecution/StopExecution
        # (they're scoped to execution ARNs, not the state machine ARN) --
        # the interceptor needs both for its poll loop.
        interceptor_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["states:DescribeExecution", "states:StopExecution"],
                resources=[
                    f"arn:aws:states:{self.region}:{self.account}:execution:"
                    f"{state_machine.state_machine_name}:*"
                ],
            )
        )

        CfnOutput(self, "BucketName", value=bucket.bucket_name)
        CfnOutput(self, "InterceptorFunctionArn", value=interceptor_fn.function_arn)
        CfnOutput(self, "StateMachineArn", value=state_machine.state_machine_arn)
        CfnOutput(self, "ResumeHandlerUrl", value=resume_url.url)
