# aws-ses-relay

A single AWS Lambda function, written in Rust, that forwards inbound email
received by Amazon SES. SES receives mail for a domain you control, stores the
raw message in S3, and invokes this function; the function reads the raw bytes
from S3, rewrites the headers so SES will accept the message for sending, and
re-sends it to the destination(s) you configure. It is configured entirely by
environment variables — no addresses, domains, or bucket names are ever written
into the source.

## How it works

```
sender ──▶ SES receiving ──▶ S3 (raw message) ──▶ this Lambda ──▶ SESv2 SendEmail ──▶ your mailbox
```

SES will not send "from" a domain you do not control, so the function rewrites
each message before re-sending:

- **`From`** is rewritten to your verified sender address, preserving the
  original display name.
- **`Reply-To`** is set to the original `From` (unless the message already has a
  `Reply-To`), so replies reach the real sender.
- **`Return-Path`**, **`Sender`**, **`Message-ID`**, and every
  **`DKIM-Signature`** are removed (SES sets its own; the inherited DKIM
  signatures no longer match the rewritten message).
- Optionally, a prefix is prepended to the **`Subject`**.

The message body is preserved exactly, byte for byte. Header parsing is a linear
byte scan — non-UTF-8 mail is never corrupted, and there is no regular
expression that could backtrack catastrophically on a hostile message.

A message is **dropped** (not forwarded, returning success) when no destination
matches, when the virus verdict is `FAIL`, or when the spam verdict is `FAIL`
and `DROP_SPAM` is enabled. A drop does not delete the S3 object.

## Design notes

Rust was chosen deliberately: byte-level message handling means non-UTF-8 mail
cannot be corrupted; the header parser is linear-time, so a hostile message
cannot cause a catastrophic-backtracking denial of service; and the runtime has
the lowest memory footprint and fastest cold start, which gives the best
cost/concurrency profile if the project is adopted at high volume. (For a
low-volume forwarder, raw speed is irrelevant — the job is I/O-bound, spending
its time waiting on S3 and SES.)

## Setup

SES email receiving is only available in [certain AWS
regions](https://docs.aws.amazon.com/ses/latest/dg/regions.html#region-receive-email).
Create the S3 bucket and this Lambda in the **same region** as the SES receipt
rule.

1. **Verify your domain in SES** and publish the **MX record** it gives you so
   inbound mail is routed to SES.

2. **Create the S3 bucket** SES will write to. Keep **Object Ownership =
   "Bucket owner enforced"** (the default) — this function uses no ACLs and
   relies on that setting. **Do not enable KMS encryption on the receipt rule's
   S3 action**: SES would envelope-encrypt the object, and a plain `GetObject`
   would return ciphertext. (SSE-S3 / bucket default encryption is fine.)

3. **Add a bucket policy** that lets SES write to the bucket. AWS provides the
   exact policy when you add the S3 action; it grants `s3:PutObject` to
   `ses.amazonaws.com` for your account and rule.

4. **Create the receipt rule** with an **S3 action** (to store the message)
   followed by a **Lambda action** (to invoke this function).

   > **Object key.** SES stores each message at an object key equal to its
   > `messageId`, optionally under a key prefix you set on the S3 action. This
   > function derives the object key from the event's `messageId`, so **leave
   > the S3 action's object key prefix empty**. (If the event happens to carry
   > explicit S3-action fields — for example via an SNS-wrapped delivery — the
   > function uses those instead, and refuses any bucket other than
   > `EMAIL_BUCKET`.)

## Configuration

All configuration is via environment variables. Invalid configuration fails the
cold start and reports **every** problem at once.

| Variable | Required | Default | Description |
|---|---|---|---|
| `FROM_EMAIL` | yes | — | The verified-domain address all forwarded mail is sent as. |
| `EMAIL_BUCKET` | yes | — | The S3 bucket SES writes inbound mail to. Also an allowlist: the function refuses to read from any other bucket. |
| `FORWARD_MAPPING` | yes | — | JSON object mapping match keys to non-empty arrays of destination addresses (see below). |
| `SUBJECT_PREFIX` | no | none | Prepended to the `Subject` when non-empty (e.g. `"[EXT] "` — include the trailing space you want). |
| `ALLOW_PLUS_SIGN` | no | `true` | When `true`, a `+tag` suffix on the recipient mailbox is stripped before matching (`info+sales@…` matches as `info@…`). Accepts only `true`/`false`, case-insensitive. |
| `DROP_SPAM` | no | `false` | When `true`, messages whose spam verdict is `FAIL` are dropped. Accepts only `true`/`false`, case-insensitive. |

### `FORWARD_MAPPING`

A JSON object string. Keys are match keys (lowercased automatically); values are
non-empty arrays of destination addresses. Keys are matched in this precedence,
first match wins:

1. a full address — `"user@example.com"`
2. a whole domain — `"@example.com"` (any mailbox at that domain)
3. a bare mailbox — `"info"` (that mailbox at any domain)
4. `"@"` — catch-all for anything not matched above

```json
{
  "info@example.com": ["ops@example.net"],
  "@example.com":     ["catch-all@example.net"],
  "@":                ["fallback@example.net"]
}
```

> **Size limit.** Lambda caps total environment variables at 4 KB, which bounds
> how large `FORWARD_MAPPING` can be.

> **`DROP_SPAM` is inert** unless spam/virus scanning is enabled on the SES
> receipt rule; otherwise the verdict status is `DISABLED` and nothing is
> dropped. "Drop" means "do not forward" — the S3 object still exists.

## Least-privilege IAM

The function's execution role needs only:

- **`s3:GetObject`** on the inbound objects, e.g.
  `arn:aws:s3:::YOUR_BUCKET/*` (scope to your key prefix if you use one).
- **`ses:SendEmail`** *and* **`ses:SendRawEmail`** on `arn:aws:ses:REGION:ACCOUNT:identity/*`.

  > While SES is in the **sandbox**, a send is authorized against the verified
  > *recipient* identity as well, so scoping to a single sender identity fails
  > with `AccessDenied`. Scoping to `identity/*` avoids that; tighten it once
  > you are out of the sandbox if you wish.

- **CloudWatch Logs** write (`logs:CreateLogGroup`, `logs:CreateLogStream`,
  `logs:PutLogEvents`) — covered by the AWS-managed
  `AWSLambdaBasicExecutionRole`.

## Build and deploy

```sh
# Cross-compile for the Lambda runtime (ARM64, no Docker required).
cargo lambda build --release --arm64

# Deploy (creates or updates the function).
cargo lambda deploy \
  --enable-function-url=false \
  --env-var FROM_EMAIL=relay@example.com \
  --env-var EMAIL_BUCKET=your-inbound-bucket \
  --env-var 'FORWARD_MAPPING={"@example.com":["you@example.net"]}'
```

Alternatively, zip the produced `bootstrap` binary and upload it to a function
you create manually.

- **Runtime:** `provided.al2023` (OS-only). **Architecture:** ARM64 (Graviton).
- **Memory:** 256–512 MB (headroom for a large message held as bytes).
- **Timeout:** ~30 seconds.

## Failure handling

SES invokes Lambda **asynchronously**: on failure it retries twice and then
**drops the event**, while the message remains in S3. To avoid silently losing
mail:

- Configure an **OnFailure destination** (an SNS topic or SQS dead-letter
  queue) on the function's async invocation config, **or** at minimum a
  **CloudWatch alarm** on the function's `Errors` metric.
- To **replay** a failed message, re-invoke the function with an event that
  points at the stored S3 object (the object key is the message's `messageId`).

## Scaling to high volume

The real ceiling is your **SES sending quota** (messages per second and per
day) — request increases before you need them. Beyond that:

- Add a dead-letter queue so nothing is lost on failure.
- Optionally put an **SQS queue in front** of the function to smooth spikes and
  cap concurrency.
- Add **idempotency** if duplicate deliveries would matter (SES async invokes
  are at-least-once).
- Tune memory for cost once you have real numbers.

## Operations

- Add an **S3 lifecycle rule** to expire stored mail after a retention period
  you choose. Dropped spam/virus mail also remains in the bucket, so lifecycle
  expiry is how you keep storage bounded.

## Limitations

- **40 MB post-base64 send cap.** SES caps a send at 40 MB after base64
  encoding, so this function refuses raw messages larger than ~30 MB.
- **Forwarding breaks SPF** (the envelope sender changes) and relies on DKIM
  alignment for DMARC. Deliverability depends on your verified domain's DKIM.
- **Watch for mail loops** with auto-responders: do not map `FROM_EMAIL` back
  into a forwarded destination.

## License

[MIT](LICENSE).
