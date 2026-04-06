# Cloud Breach Detection & Response Lab — Project Write-Up

---

## What I Built and Why

I wanted to go through a cloud security incident end to end — not just configure controls, but actually break something, detect it, and fix it properly. Most labs give you a broken environment to repair. Building from scratch meant I had to understand why each piece existed before introducing the flaw.

The setup was deliberately minimal: an EC2 instance accessible only via SSM, an IAM role, two S3 buckets (one allowed, one restricted), a log bucket, CloudTrail with S3 data events enabled, and GuardDuty. Everything in Terraform, built and tested one step at a time before moving on.

---

## Architecture

```
EC2 (SSM only, IMDSv2, no SSH)
  └── IAM Role (breach-lab-ec2-role)
        ├── S3 data bucket        → allowed (GetObject, PutObject, ListBucket)
        ├── S3 sensitive bucket   → blocked (explicit bucket policy deny)
        └── S3 log bucket         → blocked (no-delete policy)

CloudTrail → S3 log bucket   (all regions, S3 data events on)
GuardDuty  → reads CloudTrail automatically
```

---

## The Vulnerability I Introduced

I replaced the EC2 role's scoped S3 policy with `s3:* on *`. This is a real mistake — someone needs quick access, goes too broad, and forgets to fix it. From inside the instance, the role now had full S3 access across the entire account.

The interesting part: even with that IAM policy in place, the sensitive bucket stayed protected because of the bucket policy deny. IAM is the identity-side control. The bucket policy is the resource-side control. They're independent — and that independence is what saved the sensitive data.

---

## The Attack Simulation

Running the attack from inside the SSM session was the most useful part of the project. A few things that clicked during it:

**`ListBuckets` always succeeds.** You can't block it with a bucket policy — bucket policies apply once a specific bucket is targeted. The attacker knows all bucket names before attempting anything. This means bucket naming is not a security control.

**The sensitive bucket's only protection was the bucket policy.** IAM said "allow everything." The bucket policy overrode it. If that policy hadn't been there, the credentials file was gone. One misconfigured resource away from a real breach.

**Credential harvesting via IMDS is two curl commands.** IMDSv2 stops SSRF from doing this automatically (SSRF can't do a PUT request — it can only GET). But it doesn't stop code or a person running on the instance from harvesting credentials manually. The role's scope is what limits the damage.

**The log deletion attempt got logged before it was blocked.** Every `DeleteObject` that hit the log bucket returned AccessDenied — but not before CloudTrail recorded it. The cover-tracks move became part of the evidence chain.

---

## Detection

I used `cloudtrail lookup-events` filtered by the EC2 role ARN to reconstruct the full event chain. The `lookup-events` API is convenient but incomplete — it strips error codes. The raw `.json.gz` files in the log bucket had the full picture, including `errorCode: "AccessDenied"` and the exact bucket/key targeted.

GuardDuty flagged the behavior but with a delay. In a real incident you'd be working from CloudTrail while waiting for GuardDuty to surface. The lesson: treat CloudTrail as the source of truth and GuardDuty as the alert layer on top — not the other way around.

---

## The Fix

Three independent layers:

1. **IAM policy** — restored to explicit actions on the data bucket only. This is the identity-side control.
2. **Bucket policy** — added a second deny statement on the sensitive bucket specifically targeting the EC2 role ARN. Now there are two independent deny statements. Both have to be removed to gain access.
3. **IMDSv2** — confirmed `http_tokens = required` in Terraform state output. Not a new change — validation step to prove it was set at provisioning time.

Then ran a full validation suite from inside a fresh SSM session to confirm all 11 checks passed.

---

## What Actually Went Wrong (Real Mistakes)

**The log bucket policy failed on first apply.** CloudTrail tried to validate write access before the public access block was fully in place. Fixed with `depends_on`. This taught me that Terraform resource ordering isn't always what it looks like in the file — explicit dependencies matter.

**`ListAllMyBuckets` can't be scoped to a specific bucket ARN.** AWS rejects the policy with an error that isn't immediately clear. Spent time debugging before finding the relevant docs note. It's a quirk worth remembering: some S3 actions only work with `Resource: "*"`.

**The `date` flag for CloudTrail lookup commands differs between macOS and Linux** (`-v` vs `-d`). Small but it slowed down the investigation phase.

**GuardDuty didn't fire in the first 15 minutes.** I assumed something was broken. It wasn't — it was building a baseline. The real lesson: in a real environment, some findings take hours or days to emerge from behavioral baselines. Don't tune your detection expectations to lab timelines.

---

## Trade-offs I Made

- **Default VPC** — keeps the setup minimal. In production you'd want a dedicated VPC, private subnets, NAT.
- **`force_destroy = true`** on all buckets — necessary for clean lab teardown. Never in production.
- **SSE-S3 instead of SSE-KMS** — fine for a lab. KMS gives per-key-use audit logs which matter in production.
- **GuardDuty at 15-minute intervals** — costs more than the 6-hour default. Worth it for the lab to see findings faster.

---

## What I'd Do Differently

**Add S3 Object Lock (WORM) to the log bucket.** The no-delete bucket policy works, but Object Lock is enforced at the storage layer — no policy change can override it. That's the right production control.

**Add a CloudWatch alarm on GuardDuty HIGH findings.** Detection shouldn't depend on someone remembering to check a dashboard.

**Add explicit denies for `cloudtrail:StopLogging` and `guardduty:DeleteDetector`** directly on the EC2 role. Currently those fail because the role has no permission — which works — but an explicit deny is more intentional and survives future policy additions.

**Complete the credential exfiltration path.**
After harvesting IMDS credentials from inside EC2, the next
step is exporting them to an external machine and running AWS
CLI commands using those credentials. The key detection signal
is the source IP change in CloudTrail — same IAM role ARN,
different IP address. That anomaly is what a SOC analyst looks
for when investigating suspected credential theft. The correct
response is time-based session revocation using the
aws:TokenIssueTime condition, which kills all active sessions
issued before the compromise without rotating the role itself.

---

## What I Can Speak to in an Interview

- Why explicit deny beats IAM allow regardless of where the allow comes from
- What IMDSv2 actually protects against — and what it doesn't
- Why CloudTrail data events need to be explicitly enabled and what you miss without them
- How GuardDuty ingests CloudTrail without configuration and why the detection lag matters
- How a single overpermissive IAM policy can expose an account's data while everything else looks fine
- The difference between identity-side and resource-side access control — and why you need both
