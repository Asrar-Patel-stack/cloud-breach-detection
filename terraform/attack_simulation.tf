# ============================================================
# ATTACK SIMULATION — OVERPERMISSIVE IAM POLICY
#
# HOW TO USE:
# 1. Comment out aws_iam_policy.ec2_s3_policy in main.tf
# 2. Uncomment this file (remove the /* and */ below)
# 3. Run: terraform apply
# 4. Run the attack simulation from inside SSM
# 5. When done: re-enable main.tf policy, comment this out, apply again
#
# DO NOT leave this active — it's the intentional vulnerability
# ============================================================

/*
resource "aws_iam_policy" "ec2_s3_policy" {
  name        = "breach-lab-ec2-s3-policy"
  description = "INTENTIONALLY OVERPERMISSIVE — attack simulation only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "OverpermissiveS3Access"
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      }
    ]
  })
}
*/
