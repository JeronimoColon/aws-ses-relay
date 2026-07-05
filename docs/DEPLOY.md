# Deploying aws-ses-relay from scratch

A complete, ordered runbook to go from nothing to a working inbound-email
forwarder. Every command is copy-paste once you fill in the placeholders. It uses
the AWS CLI; the AWS console works too, and where the console does something for
you automatically (it does, in one place) that is called out.

Read [the README](../README.md) for what each configuration value *means*; this
document is only the *how* and the *order*.

## Before you start

**Step 0 — get out of the SES sandbox (do this first).** A new AWS account's SES
is in the **sandbox**, where you can send only to email addresses you have
*verified in advance*, at a low quota. A forwarder's entire job is sending to real
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
| `YOUR_OWNER` | Your GitHub org/user, for downloading releases |

The example commands assume `FROM_EMAIL=relay@YOUR_DOMAIN` and a `FORWARD_MAPPING`
of `{"@YOUR_DOMAIN":["you@example.net"]}`. Adjust to your mapping (see the README).

**Working directory.** Clone this repository and run every command below **from
the repo root** — the policy steps reference the `deploy/**/*.json` files with
`file://` paths relative to that root. This is true even if you download the
release artifact rather than build (the artifact is only the binary; the policy
files come from the repo).

**Substitute every placeholder before applying any policy.** AWS accepts a policy
containing a leftover `YOUR_*` token as *syntactically valid* and returns
success — then it silently misbehaves. The worst case: a leftover
`YOUR_RULE_SET`/`YOUR_RULE` in the bucket policy's `aws:SourceArn` makes S3
**reject every real SES write**, so mail is never stored and nothing errors at
deploy time. After editing the `deploy/` files, confirm none remain:

```sh
grep -rn 'YOUR_' deploy/   # must print nothing before you apply the policies
```

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

`create-email-identity` returns three **DKIM tokens**, not ready-made records.
Turn each token into a CNAME:

    Name:  <token>._domainkey.YOUR_DOMAIN
    Value: <token>.dkim.amazonses.com

Also publish an **MX** record for `YOUR_DOMAIN` pointing at SES's inbound endpoint
for your region (`inbound-smtp.YOUR_REGION.amazonaws.com`, priority 10). The DKIM
CNAMEs are what **verify the identity** (and sign outbound mail), so the wait
below does not finish until they resolve; the MX record routes inbound mail to
SES. If you'd rather not build the CNAMEs by hand, the console's **"Publish DNS
records"** view shows them ready to copy. Wait for the identity to show as
verified:

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

## Step 5 — Create the execution role

This is the identity the *function* runs as. Fill the placeholders in
[`deploy/iam/lambda-execution-policy.json`](../deploy/iam/lambda-execution-policy.json)
first — it grants S3 read + SES send, which is everything the default
(idempotency-off) deploy needs. Duplicate suppression adds one more policy later,
only if you turn it on — see [the optional section](#optional--enable-duplicate-suppression-idempotency).

```sh
# Trust policy lets Lambda assume the role.
aws iam create-role --role-name aws-ses-relay \
  --assume-role-policy-document file://deploy/iam/lambda-trust-policy.json

# CloudWatch Logs write access.
aws iam attach-role-policy --role-name aws-ses-relay \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# S3 read + SES send.
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
  --environment '{"Variables":{"FROM_EMAIL":"relay@YOUR_DOMAIN","EMAIL_BUCKET":"YOUR_INBOUND_BUCKET","FORWARD_MAPPING":"{\"@YOUR_DOMAIN\":[\"you@example.net\"]}"}}'
```

> **Why the JSON `--environment` form, not `Variables={...}`?** `FORWARD_MAPPING`
> is itself JSON, and the CLI's `Variables={...}` shorthand cannot carry a JSON
> value — it splits on the commas and chokes on the colons, so the command
> errors out before it reaches AWS. Pass the full JSON structure and encode
> `FORWARD_MAPPING` as an **escaped JSON string** (note the `\"`). Duplicate
> suppression is off by default; turn it on later via
> [the optional section](#optional--enable-duplicate-suppression-idempotency).

`--handler bootstrap` is a required placeholder that the OS-only
`provided.al2023` runtime ignores (your `bootstrap` executable is the
entrypoint). If `create-function` returns *"The role defined for the function
cannot be assumed by Lambda"*, the role from Step 5 hasn't finished propagating —
wait ~10 seconds and re-run. Grab the function ARN for the next steps:

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

> **On an account that already receives mail, read this first.** Only one receipt
> rule set can be **active** per region, and `set-active-receipt-rule-set` below
> **deactivates whatever set was active before** — silently turning off your
> existing receiving. (`create-receipt-rule-set` also errors if a set of that
> name already exists.) If the account already has an active set
> (`aws ses describe-active-receipt-rule-set` shows it), **skip the create and
> activate commands** and add just the rule to that existing set instead. The
> commands below are for a fresh account with no active set.

Create the rule set, add the rule with an **S3 action first** then a **Lambda
action second**, and make the rule set active. Note the empty S3 key prefix — the
function derives the object key from the message id, so a prefix would break
reads.

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
notes).

If `create-receipt-rule` reports it **cannot write to the bucket**, SES's
write-check failed against the Step 4 bucket policy: confirm its `aws:SourceArn`
exactly matches this rule's ARN and `aws:SourceAccount` is your account id.

## Step 9 — Smoke test

Send a real email from an outside account to an address that matches your
`FORWARD_MAPPING` (e.g. `anything@YOUR_DOMAIN`) and confirm it arrives at the
destination.

If it doesn't, read the logs — the function logs message ids, recipients,
verdicts, and its decision as JSON. The log group is created on the **first**
invocation, so it won't exist until at least one message has been sent:

```sh
aws logs tail /aws/lambda/aws-ses-relay --region YOUR_REGION --since 10m --follow
```

Common first-deploy causes: still in the **SES sandbox** (Step 0) so the send is
denied; the destination bounced; or an IAM/`AccessDenied` message pointing at a
missing permission from Step 5. You can also reprocess a stored message directly
with a minimal replay event. Write the payload first, substituting a real stored
`messageId` and a recipient that matches your `FORWARD_MAPPING`:

```sh
cat > replay-event.json <<'JSON'
{
  "Records": [{
    "eventSource": "aws:ses",
    "ses": {
      "mail": { "messageId": "THE_MESSAGE_ID" },
      "receipt": {
        "recipients": ["anything@YOUR_DOMAIN"],
        "spamVerdict": { "status": "PASS" },
        "virusVerdict": { "status": "PASS" },
        "action": { "type": "Lambda" }
      }
    }
  }]
}
JSON

aws lambda invoke --function-name aws-ses-relay --region YOUR_REGION \
  --cli-binary-format raw-in-base64-out --payload file://replay-event.json /dev/stdout
```

> If duplicate suppression is enabled and this message's marker still exists (it
> was already forwarded, or its TTL hasn't elapsed), the replay is treated as a
> duplicate and does nothing (returns success, sends nothing). Delete
> `idempotency/<messageId>` from the marker bucket, or wait out the TTL, before
> replaying.

## Step 10 — Operational hardening

```sh
# Do not lose mail on repeated failure: send failed async invokes to a queue.
# Create the queue first, and grant the *execution role* sqs:SendMessage on it --
# Lambda writes the on-failure record using the function's own role, so without
# this permission failed events are silently dropped. (Edit the queue ARN in
# deploy/iam/dlq-send-policy.json to match your region/account.)
aws sqs create-queue --queue-name aws-ses-relay-dlq --region YOUR_REGION
aws iam put-role-policy --role-name aws-ses-relay \
  --policy-name aws-ses-relay-dlq \
  --policy-document file://deploy/iam/dlq-send-policy.json
aws lambda put-function-event-invoke-config --function-name aws-ses-relay \
  --region YOUR_REGION --maximum-retry-attempts 2 \
  --destination-config '{"OnFailure":{"Destination":"arn:aws:sqs:YOUR_REGION:YOUR_ACCOUNT_ID:aws-ses-relay-dlq"}}'

# Bound CloudWatch cost/retention (recipient addresses appear in logs). The log
# group is created on the first invocation; create it explicitly so retention
# can be set before then.
aws logs create-log-group --log-group-name /aws/lambda/aws-ses-relay \
  --region YOUR_REGION 2>/dev/null || true
aws logs put-retention-policy --log-group-name /aws/lambda/aws-ses-relay \
  --region YOUR_REGION --retention-in-days 30

# Expire stored mail (edit the day count in deploy/s3/lifecycle.json first).
aws s3api put-bucket-lifecycle-configuration --bucket YOUR_INBOUND_BUCKET \
  --lifecycle-configuration file://deploy/s3/lifecycle.json
```

For an SNS on-failure topic instead of SQS, grant the role `sns:Publish` on the
topic rather than `sqs:SendMessage`. Also consider a CloudWatch alarm on the
function's `Errors` metric. The lifecycle rule expires **current** object
versions; if you enable S3 **versioning** on the bucket, add a
`NoncurrentVersionExpiration` rule too, or noncurrent copies of raw email outlive
the expiry. See the README's "Scaling to high volume" and "Operations" sections
for the reasoning behind each of these.

## Optional — enable duplicate suppression (idempotency)

By default idempotency is **off** and the forwarder is plain at-least-once — a
rare duplicate SES delivery may forward twice (see the README's "Idempotency"
section for the trade-offs and edge cases). To turn it on, pick a marker bucket —
a **separate** bucket keeps the mail bucket single-purpose — and run:

```sh
# 1. Create the marker bucket (skip if you reuse the inbound bucket).
aws s3api create-bucket --bucket YOUR_IDEMPOTENCY_BUCKET --region YOUR_REGION \
  --create-bucket-configuration LocationConstraint=YOUR_REGION
# (omit --create-bucket-configuration in us-east-1)

# 2. Let the function write and delete markers (edit the ARN in the file first).
aws iam put-role-policy --role-name aws-ses-relay \
  --policy-name aws-ses-relay-idempotency \
  --policy-document file://deploy/iam/idempotency-policy.json

# 3. Point the function at the bucket. NOTE: --environment REPLACES the whole
#    variable set, so repeat every existing variable plus IDEMPOTENCY_BUCKET.
aws lambda update-function-configuration --function-name aws-ses-relay \
  --region YOUR_REGION \
  --environment '{"Variables":{"FROM_EMAIL":"relay@YOUR_DOMAIN","EMAIL_BUCKET":"YOUR_INBOUND_BUCKET","FORWARD_MAPPING":"{\"@YOUR_DOMAIN\":[\"you@example.net\"]}","IDEMPOTENCY_BUCKET":"YOUR_IDEMPOTENCY_BUCKET"}}'

# 4. Expire markers so an orphaned one self-heals (a few days, comfortably past
#    the SES retry window). This applies to the SEPARATE marker bucket.
aws s3api put-bucket-lifecycle-configuration --bucket YOUR_IDEMPOTENCY_BUCKET \
  --lifecycle-configuration file://deploy/s3/lifecycle-idempotency.json
```

> **Reusing the inbound bucket for markers?** `put-bucket-lifecycle-configuration`
> **replaces** a bucket's entire lifecycle configuration — so applying the
> markers-only file to the inbound bucket would erase the 30-day mail-expiry rule
> from Step 10, leaving raw email stored forever. For a single shared bucket,
> **skip** both separate lifecycle applies and apply the combined file once (it
> carries both rules; where an object matches both, S3 uses the sooner, 4-day
> expiry):
>
> ```sh
> aws s3api put-bucket-lifecycle-configuration --bucket YOUR_INBOUND_BUCKET \
>   --lifecycle-configuration file://deploy/s3/lifecycle-combined.json
> ```

## Updating later

New code, same infrastructure — just push the new artifact:

```sh
aws lambda update-function-code --function-name aws-ses-relay --region YOUR_REGION \
  --zip-file fileb://bootstrap-arm64.zip
```

Change configuration without redeploying code with
`aws lambda update-function-configuration --environment ...`.
