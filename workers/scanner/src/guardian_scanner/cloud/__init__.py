"""Cloud security posture (WP-D8).

The engine that existed evaluated a snapshot schema Guardian invented: `{"storage": [{"name": …,
"public": true}]}`. Nothing produces that. Every real input — the AWS CLI, an AWS Config export, a
`boto3` collector, Security Hub — emits the API's own shapes, so in practice the engine could only
run against a fixture somebody wrote by hand for it, and the interesting judgement (*is this bucket
public?*) had already been made by whoever filled in the boolean.

This package takes the API shapes as they are and makes the judgement itself:

* an S3 bucket is public if its **policy** grants a wildcard principal, or its **ACL** grants
  `AllUsers`/`AuthenticatedUsers`, and its **public access block** does not override that — three
  sources that disagree with each other constantly, which is exactly why a boolean was useless;
* an IAM principal is over-permissioned according to its **policy documents** — wildcard actions,
  `NotAction` grants, and the specific actions that let a principal grant itself more (`iam:*`,
  `iam:PassRole` with a wildcard resource, `sts:AssumeRole` on `*`);
* a security group is open according to its **port ranges**, not an exact port match: the previous
  rule compared `port == 22`, so `FromPort: 0, ToPort: 65535` — which exposes SSH along with
  everything else — matched nothing.

Everything here is pure. A collector that calls AWS is a separate concern behind the same input
shape, so the rules are tested against recorded API responses without a cloud account.
"""

from __future__ import annotations
