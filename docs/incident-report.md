# IR-2024-001 — Cloud Breach Detection & Response Lab

**Classification:** Internal / Learning Exercise  
**Status:** Resolved

---

## Summary

An EC2 instance role was given `s3:* on *`. After landing on the instance via SSM, an attacker enumerated all buckets, read and wrote to the data bucket, and harvested temporary credentials via IMDS. The sensitive bucket and log bucket stayed protected due to explicit resource-level deny policies. The full attack chain was reconstructed from CloudTrail.

---

## Timeline

| Time | Event | Result |
|------|-------|--------|
| T+00:00 | IAM policy changed to `s3:*` | Vulnerability introduced |
| T+00:01 | SSM session opened | — |
| T+00:02 | `ListBuckets` — all 3 buckets enumerated | ✅ Success |
| T+00:03 | `GetObject` on sensitive bucket | ❌ AccessDenied |
| T+00:04 | `GetObject` + `PutObject` on data bucket | ✅ Success |
| T+00:05 | IAM credentials pulled via IMDSv2 | ✅ Exposed (temporary) |
| T+00:06 | `DeleteObject` on log bucket | ❌ AccessDenied |
| T+00:06 | `StopLogging` on CloudTrail | ❌ AccessDenied |
| T+00:07 | `DeleteDetector` on GuardDuty | ❌ AccessDenied |
| T+00:08 | SSM session terminated | — |
| T+00:09 | Credentials exported to external machine | ✅ Simulated |
| T+00:10 | `ListBuckets` from external IP | ✅ Would succeed |
| T+00:10 | `GetObject` from data bucket — external IP | ✅ Would succeed |
| T+00:11 | Source IP change detected in CloudTrail | ✅ Key detection signal |

---

## Affected Resources

| Resource | Status | Detail |
|----------|--------|--------|
| S3 data bucket | 🔴 Compromised | Read + write. `backdoor.txt` written, `testfile.txt` exfiltrated. |
| IAM role credentials | 🟡 Exposed | Temporary — expired automatically. |
| S3 sensitive bucket | 🟢 Protected | Bucket policy held despite `s3:*` IAM allow. |
| S3 log bucket | 🟢 Protected | No-delete policy blocked all deletion attempts. |
| CloudTrail | 🟢 Intact | Full event chain captured including denied actions. |
| GuardDuty | 🟢 Active | Findings raised within 15–30 minutes. |

---

## Root Cause

IAM policy was too broad. The sensitive bucket's protection depended entirely on a bucket policy — not on the IAM role being correctly scoped. If that bucket policy hadn't existed, the credentials file would have been accessible. One misconfigured resource-level policy away from a full data breach.

---

## Detection

**CloudTrail** captured every event including denied ones. Raw `.json.gz` log files had error codes and exact request parameters that the `lookup-events` API strips out — those were needed to confirm AccessDenied events precisely.

**GuardDuty** flagged the anomalous S3 access pattern with a ~15–30 minute delay. CloudTrail was the source of truth throughout the investigation; GuardDuty was the alert layer on top.

---

## Detection Signals

| Signal | Source | Detail |
|--------|--------|--------|
| EC2 source IP | CloudTrail | 18.x.x.x — normal instance traffic |
| External source IP | CloudTrail | attacker home IP — same role ARN |
| IP change on same ARN | CloudTrail | Primary exfiltration indicator |
| GuardDuty delay | GuardDuty | 15–30 min lag — CloudTrail is ground truth |

The source IP shift on the same IAM role ARN is the clearest
signal that credentials left the instance and were used
externally. In a real incident this triggers immediate
session revocation using aws:TokenIssueTime condition.

---

## Blast Radius

Contained to the S3 data bucket (read + write). The role had no permissions for IAM, EC2, Secrets Manager, CloudTrail management, or GuardDuty — all returned AccessDenied during enumeration.

---

## Remediation

1. **IAM policy replaced** — scoped to `GetObject`, `PutObject`, `ListBucket` on data bucket only. `ListAllMyBuckets` on `*` retained (AWS limitation — this action cannot be resource-scoped).
2. **Sensitive bucket hardened** — second explicit deny added targeting the EC2 role ARN directly. Both deny statements must now be independently removed to gain access.
3. **IMDSv2 enforcement confirmed** — `http_tokens = required`, `hop_limit = 1` verified in Terraform state output.
4. **`backdoor.txt` removed** from data bucket.

---

## Validation (Post-Fix)

| Check | Expected | Result |
|-------|----------|--------|
| Data bucket `GetObject` | Success | ✅ Pass |
| Data bucket `PutObject` | Success | ✅ Pass |
| Data bucket `ListBucket` | Success | ✅ Pass |
| Sensitive bucket `ListObjects` | AccessDenied | ✅ Pass |
| Sensitive bucket `GetObject` | AccessDenied | ✅ Pass |
| Sensitive bucket `PutObject` | AccessDenied | ✅ Pass |
| Log bucket `ListObjects` | AccessDenied | ✅ Pass |
| `DeleteObject` on data bucket | AccessDenied | ✅ Pass |
| IMDSv1 request | Rejected | ✅ Pass |
| IMDSv2 with token | Success | ✅ Pass |
| `backdoor.txt` removed | Confirmed gone | ✅ Pass |

---

## Key Takeaways

- The bucket policy — not the IAM policy — stopped data loss. IAM was the broken control. Resource-side deny is the safety net that holds when identity-side access control fails.
- Denied requests are still logged. The log deletion attempt became part of the evidence chain.
- GuardDuty took 15–30 minutes. CloudTrail was the ground truth the entire time.
- IMDSv2 blocks SSRF-based credential theft (requires a PUT, not just GET). It does not block a process or person running on the instance from harvesting credentials. Least-privilege IAM is what limits the blast radius when credentials are exposed.
