# Deploying aws-ses-relay from scratch

A complete, ordered runbook to go from nothing to a working inbound-email
forwarder. Every command is copy-paste once you fill in the placeholders. It uses
the AWS CLI; the AWS console works too, and where the console does something for
you automatically (it does, in one place) that is called out.

Read [the README](../README.md) for what each configuration value *means*; this
document is only the *how* and the *order*.

## Before you start

**Blocker you must handle: the SES sandbox.** A new AWS account's SES is in the
**sandbox**, where you can send only to email addresses you have *verified in
advance*, at a low quota. A forwarder's entire job is sending to real
destinations, so **in the sandbox every forward fails.** Request production
access early (it can take a day to be granted):

```sh
aws sesv2 put-account-details \
  --production-access-enabled \
  --mail-type TRANSACTIONAL \
  --website-url https://example.com \
  --use-case-description "Forwarding inbound mail received by SES to internal mailboxes." \
  --region YOUR_REGION
```

You can build and wire everything below while access is pending; just don't
expect real forwards to land until it's granted (or, to test sooner, verify a
destination address and forward only to it).

**Region.** SES email *receiving* is only available in
[certain regions](https://docs.aws.amazon.com/ses/latest/dg/regions.html#region-receive-email).
Put the S3 bucket, the Lambda, and the SES receipt rule all in that **same
region**.

**Tools.**

- `aws` CLI v2, configured with credentials that can manage IAM, S3, Lambda, and
  SES.
- To get the deployable artifact you either **download a release** (needs `gh`,
  the GitHub CLI) or **build it** (needs the Rust stable toolchain, the
  `aarch64-unknown-linux-gnu` target, `cargo-lambda`, and `zig` — see the
  versions pinned in [`.github/workflows/release.yml`](../.github/workflows/release.yml)).

**Placeholders used throughout** (substitute your real values — never commit real
ones):

| Placeholder | Meaning |
|---|---|
| `YOUR_REGION` | An SES-receiving region, e.g. `us-east-1` |
| `YOUR_ACCOUNT_ID` | Your 12-digit AWS account id |
| `YOUR_DOMAIN` | The domain you receive mail for, e.g. `example.com` |
| `YOUR_INBOUND_BUCKET` | S3 bucket SES writes raw mail to |
| `YOUR_IDEMPOTENCY_BUCKET` | Bucket for duplicate-suppression markers (may equal the inbound bucket) |
| `YOUR_RULE_SET` / `YOUR_RULE` | SES receipt-rule-set and rule names you choose |

The example commands assume `FROM_EMAIL=relay@YOUR_DOMAIN` and a `FORWARD_MAPPING`
of `{"@YOUR_DOMAIN":["you@example.net"]}`. Adjust to your mapping (see the README).

---

## Step 1 — Get the deployment artifact

**Option A — download a published release** (recommended):

```sh
gh release download <tag> --repo YOUR_OWNER/aws-ses-relay --pattern 'bootstrap-arm64.zip'
```

Pick a tag from the repo's Releases page (for example a `v0.1.0-rc.N` pre-release
while dogfooding, or `v0.1.0` once cut).

**Option B — build it yourself:**

```sh
cargo lambda build --release --arm64
# produces target/lambda/bootstrap/bootstrap
( cd target/lambda/bootstrap && zip -X ../../../bootstrap-arm64.zip bootstrap )
```

Either way you end up with **`bootstrap-arm64.zip`**, a package containing a
single executable named `bootstrap`, built for ARM64.

## Step 2 — Verify your domain in SES and route mail to it

```sh
aws sesv2 create-email-identity --email-identity YOUR_DOMAIN --region YOUR_REGION
```

Publish the DNS records SES returns: the **DKIM** CNAMEs (for deliverability) and
an **MX** record pointing mail for `YOUR_DOMAIN` at SES's inbound endpoint for
your region (`inbound-smtp.YOUR_REGION.amazonaws.com`, priority 10). Wait for the
identity to show as verified:

```sh
aws sesv2 get-email-identity --email-identity YOUR_DOMAIN --region YOUR_REGION \
  --query VerifiedForSendingStatus
```

## Step 3 — Create the inbound S3 bucket (hardened)

```sh
aws s3api create-bucket --bucket YOUR_INBOUND_BUCKET --region YOUR_REGION \
  --create-bucket-configuration LocationConstraint=YOUR_REGION
# (omit --create-bucket-configuration in us-east-1)

aws s3api put-public-access-block --bucket YOUR_INBOUND_BUCKET \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Object Ownership is **Bucket owner enforced** by default (this function uses no
ACLs and relies on that). Leave at-rest encryption at the account default
(**SSE-S3**). **Do not** put a KMS key on the SES S3 action later — SES would
envelope-encrypt the object and a plain `GetObject` would return ciphertext.

## Step 4 — Apply the bucket policy (TLS-only + let SES write)

Edit [`deploy/s3/inbound-bucket-policy.json`](../deploy/s3/inbound-bucket-policy.json),
replacing the placeholders (it grants `s3:PutObject` to `ses.amazonaws.com`,
scoped to your account and the rule ARN you'll create in Step 8, and denies any
non-TLS request), then:

```sh
aws s3api put-bucket-policy --bucket YOUR_INBOUND_BUCKET \
  --policy file://deploy/s3/inbound-bucket-policy.json
```

> If you use a **separate** idempotency bucket, create it the same way (Step 3);
> it needs no SES policy, only the Lambda's write permission (Step 5).

## Step 5 — Create the execution role

This is the identity the *function* runs as. Fill the placeholders in
[`deploy/iam/lambda-execution-policy.json`](../deploy/iam/lambda-execution-policy.json)
first (drop the `IdempotencyMarkers` statement if you won't set
`IDEMPOTENCY_BUCKET`).

```sh
# Trust policy lets Lambda assume the role.
aws iam create-role --role-name aws-ses-relay \
  --assume-role-policy-document file://deploy/iam/lambda-trust-policy.json

# CloudWatch Logs write access.
aws iam attach-role-policy --role-name aws-ses-relay \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# S3 read + SES send (+ optional idempotency writes).
aws iam put-role-policy --role-name aws-ses-relay \
  --policy-name aws-ses-relay-permissions \
  --policy-document file://deploy/iam/lambda-execution-policy.json
```

## Step 6 — Create the Lambda function

```sh
aws lambda create-function --function-name aws-ses-relay --region YOUR_REGION \
  --runtime provided.al2023 --architectures arm64 --handler bootstrap \
  --role arn:aws:iam::YOUR_ACCOUNT_ID:role/aws-ses-relay \
  --zip-file fileb://bootstrap-arm64.zip \
  --memory-size 512 --timeout 30 \
  --environment 'Variables={FROM_EMAIL=relay@YOUR_DOMAIN,EMAIL_BUCKET=YOUR_INBOUND_BUCKET,FORWARD_MAPPING={"@YOUR_DOMAIN":["you@example.net"]}}'
```

`--handler bootstrap` is a required placeholder that the OS-only
`provided.al2023` runtime ignores (your `bootstrap` executable is the
entrypoint). To also set idempotency, add `IDEMPOTENCY_BUCKET=...` to the
variables. Grab the function ARN for the next steps:

```sh
aws lambda get-function --function-name aws-ses-relay --region YOUR_REGION \
  --query Configuration.FunctionArn --output text
```

> **The next two steps have a deliberate order** because of a circular
> dependency: the SES rule (Step 8) must reference the function ARN, and SES
> refuses to create a rule it isn't allowed to invoke — so the invoke permission
> (Step 7) must exist **first**, scoped to the rule ARN you're about to create.
> The rule ARN is predictable from the names you chose:
> `arn:aws:ses:YOUR_REGION:YOUR_ACCOUNT_ID:receipt-rule-set/YOUR_RULE_SET:receipt-rule/YOUR_RULE`.
> (The AWS **console** adds this permission for you when you add the Lambda
> action; via CLI you do it explicitly, below.)

## Step 7 — Let SES invoke the function

```sh
aws lambda add-permission --function-name aws-ses-relay --region YOUR_REGION \
  --statement-id AllowSESInvoke \
  --action lambda:InvokeFunction \
  --principal ses.amazonaws.com \
  --source-account YOUR_ACCOUNT_ID \
  --source-arn arn:aws:ses:YOUR_REGION:YOUR_ACCOUNT_ID:receipt-rule-set/YOUR_RULE_SET:receipt-rule/YOUR_RULE
```

Grant this to **no other principal**. The handler trusts any well-formed event
it receives, so invocation must be locked to SES.

## Step 8 — Create the SES receipt rule

Create (or reuse) a rule set, add the rule with an **S3 action first** then a
**Lambda action second**, and make the rule set active. Note the empty S3 key
prefix — the function derives the object key from the message id, so a prefix
would break reads.

```sh
aws ses create-receipt-rule-set --rule-set-name YOUR_RULE_SET --region YOUR_REGION

aws ses create-receipt-rule --rule-set-name YOUR_RULE_SET --region YOUR_REGION \
  --rule '{
    "Name": "YOUR_RULE",
    "Enabled": true,
    "ScanEnabled": true,
    "TlsPolicy": "Require",
    "Recipients": ["YOUR_DOMAIN"],
    "Actions": [
      { "S3Action": { "BucketName": "YOUR_INBOUND_BUCKET" } },
      { "LambdaAction": {
          "FunctionArn": "arn:aws:lambda:YOUR_REGION:YOUR_ACCOUNT_ID:function:aws-ses-relay",
          "InvocationType": "Event"
      } }
    ]
  }'

aws ses set-active-receipt-rule-set --rule-set-name YOUR_RULE_SET --region YOUR_REGION
```

`ScanEnabled: true` is what makes the spam/virus verdicts meaningful; without it
they are `DISABLED` and `DROP_SPAM`/`DROP_UNSCANNED` do nothing. `InvocationType:
Event` is the asynchronous invoke SES uses (see the README's failure-handling
notes). Only one rule set can be active per account per region.

## Step 9 — Smoke test

Send a real email from an outside account to an address that matches your
`FORWARD_MAPPING` (e.g. `anything@YOUR_DOMAIN`) and confirm it arrives at the
destination.

If it doesn't, read the logs — the function logs message ids, recipients,
verdicts, and its decision as JSON:

```sh
aws logs tail /aws/lambda/aws-ses-relay --region YOUR_REGION --since 10m --follow
```

Common first-deploy causes: still in the **SES sandbox** (Step 0) so the send is
denied; the destination bounced; or an IAM/`AccessDenied` message pointing at a
missing permission from Step 5. You can also reprocess a stored message directly
with a minimal replay event (see the README's "Failure handling"):

```sh
aws lambda invoke --function-name aws-ses-relay --region YOUR_REGION \
  --cli-binary-format raw-in-base64-out --payload file://replay-event.json /dev/stdout
```

## Step 10 — Operational hardening

```sh
# Do not lose mail on repeated failure: send failed async invokes to a DLQ/topic.
aws lambda put-function-event-invoke-config --function-name aws-ses-relay \
  --region YOUR_REGION --maximum-retry-attempts 2 \
  --destination-config '{"OnFailure":{"Destination":"arn:aws:sqs:YOUR_REGION:YOUR_ACCOUNT_ID:aws-ses-relay-dlq"}}'

# Bound CloudWatch cost/retention (recipient addresses appear in logs).
aws logs put-retention-policy --log-group-name /aws/lambda/aws-ses-relay \
  --region YOUR_REGION --retention-in-days 30

# Expire stored mail and idempotency markers (edit deploy/s3/lifecycle.json first;
# split the rules if the idempotency bucket is separate).
aws s3api put-bucket-lifecycle-configuration --bucket YOUR_INBOUND_BUCKET \
  --lifecycle-configuration file://deploy/s3/lifecycle.json
```

Also consider a CloudWatch alarm on the function's `Errors` metric. See the
README's "Scaling to high volume" and "Operations" sections for the reasoning
behind each of these.

## Updating later

New code, same infrastructure — just push the new artifact:

```sh
aws lambda update-function-code --function-name aws-ses-relay --region YOUR_REGION \
  --zip-file fileb://bootstrap-arm64.zip
```

Change configuration without redeploying code with
`aws lambda update-function-configuration --environment ...`.
