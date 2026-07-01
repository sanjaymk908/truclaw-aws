#!/usr/bin/env python3
import aws_cdk as cdk

from truclaw_stack import TruClawStack

app = cdk.App()
TruClawStack(app, "TruClawAwsStack")
app.synth()
