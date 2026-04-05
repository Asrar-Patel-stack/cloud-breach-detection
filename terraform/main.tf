# ============================================================
# CLOUD BREACH DETECTION & RESPONSE LAB
# Terraform configuration — builds the full secure baseline
# ============================================================

# ============================================================
# PROVIDER
# ============================================================
provider "aws" {
  region = var.aws_region
}

# ============================================================
# RANDOM SUFFIX — S3 bucket names must be globally unique
# ============================================================
resource "random_id" "suffix" {
  byte_length = 4
}

# ============================================================
# DATA SOURCES
# ============================================================
data "aws_caller_identity" "current" {}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ============================================================
# S3 — DATA BUCKET (allowed access)
# ============================================================
resource "aws_s3_bucket" "data_bucket" {
  bucket        = "breach-lab-data-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Name        = "BreachLab-DataBucket"
    Environment = "Lab"
    Purpose     = "Allowed access"
  }
}

resource "aws_s3_bucket_public_access_block" "data_bucket_block" {
  bucket                  = aws_s3_bucket.data_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data_bucket_sse" {
  bucket = aws_s3_bucket.data_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "data_bucket_versioning" {
  bucket = aws_s3_bucket.data_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Upload a test file so there's something to exfiltrate in the simulation
resource "aws_s3_object" "test_file" {
  bucket  = aws_s3_bucket.data_bucket.id
  key     = "testfile.txt"
  content = "this is test data"
}

# ============================================================
# S3 — SENSITIVE BUCKET (must NOT be accessible)
# ============================================================
resource "aws_s3_bucket" "sensitive_bucket" {
  bucket        = "breach-lab-sensitive-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Name        = "BreachLab-SensitiveBucket"
    Environment = "Lab"
    Purpose     = "Must NOT be accessible"
  }
}

resource "aws_s3_bucket_public_access_block" "sensitive_bucket_block" {
  bucket                  = aws_s3_bucket.sensitive_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sensitive_bucket_sse" {
  bucket = aws_s3_bucket.sensitive_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "sensitive_bucket_versioning" {
  bucket = aws_s3_bucket.sensitive_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "sensitive_bucket_deny" {
  bucket     = aws_s3_bucket.sensitive_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.sensitive_bucket_block]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Broad deny on everyone except root
        Sid    = "DenyAllExceptRoot"
        Effect = "Deny"
        Principal = { AWS = "*" }
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.sensitive_bucket.arn,
          "${aws_s3_bucket.sensitive_bucket.arn}/*"
        ]
        Condition = {
          ArnNotEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
          }
        }
      },
      {
        # Named deny on EC2 role — defense in depth
        # Both statements must be removed to gain access
        Sid    = "ExplicitDenyEC2Role"
        Effect = "Deny"
        Principal = { AWS = aws_iam_role.ec2_role.arn }
        Action   = "s3:*"
        Resource = [
          aws_s3_bucket.sensitive_bucket.arn,
          "${aws_s3_bucket.sensitive_bucket.arn}/*"
        ]
      }
    ]
  })
}

# Plant a fake credential file — the "prize" in the simulation
resource "aws_s3_object" "fake_secret" {
  bucket  = aws_s3_bucket.sensitive_bucket.id
  key     = "credentials/db-password.txt"
  content = "DB_PASSWORD=SuperSecret123!"
}

# ============================================================
# S3 — LOG BUCKET (CloudTrail destination, no delete allowed)
# ============================================================
resource "aws_s3_bucket" "log_bucket" {
  bucket        = "breach-lab-logs-${random_id.suffix.hex}"
  force_destroy = true

  tags = {
    Name        = "BreachLab-LogBucket"
    Environment = "Lab"
    Purpose     = "CloudTrail logs — no delete"
  }
}

resource "aws_s3_bucket_public_access_block" "log_bucket_block" {
  bucket                  = aws_s3_bucket.log_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket_sse" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "log_bucket_versioning" {
  bucket = aws_s3_bucket.log_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "log_bucket_policy" {
  bucket     = aws_s3_bucket.log_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.log_bucket_block]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudTrailCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.log_bucket.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/breach-lab-trail"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.log_bucket.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/breach-lab-trail"
          }
        }
      },
      {
        # Nobody can delete logs — including root, EC2 role, your IAM user
        Sid    = "DenyLogDeletion"
        Effect = "Deny"
        Principal = { AWS = "*" }
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:DeleteBucket"
        ]
        Resource = [
          aws_s3_bucket.log_bucket.arn,
          "${aws_s3_bucket.log_bucket.arn}/*"
        ]
      }
    ]
  })
}

# ============================================================
# CLOUDTRAIL
# ============================================================
resource "aws_cloudtrail" "breach_lab_trail" {
  name                          = "breach-lab-trail"
  s3_bucket_name                = aws_s3_bucket.log_bucket.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  # S3 data events — without this you won't see GetObject/PutObject
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }

  depends_on = [aws_s3_bucket_policy.log_bucket_policy]

  tags = {
    Name = "BreachLab-Trail"
  }
}

# ============================================================
# GUARDDUTY
# ============================================================
resource "aws_guardduty_detector" "breach_lab_detector" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = {
    Name = "BreachLab-GuardDuty"
  }
}

# ============================================================
# SECURITY GROUP — no inbound, HTTPS out only (SSM)
# ============================================================
resource "aws_security_group" "ec2_sg" {
  name        = "breach-lab-ec2-sg"
  description = "SSM only — no inbound ports"
  vpc_id      = data.aws_vpc.default.id

  egress {
    description = "HTTPS out for SSM and AWS API"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "BreachLab-EC2-SG"
  }
}

# ============================================================
# IAM ROLE — EC2 instance identity
# ============================================================
resource "aws_iam_role" "ec2_role" {
  name = "breach-lab-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "BreachLab-EC2-Role"
  }
}

# ============================================================
# IAM POLICY — LEAST PRIVILEGE (secure baseline)
# Switch to overpermissive_policy.tf to simulate the attack
# ============================================================
resource "aws_iam_policy" "ec2_s3_policy" {
  name        = "breach-lab-ec2-s3-policy"
  description = "Least privilege S3 — data bucket only"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowDataBucketObjectAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.data_bucket.arn}/*"
      },
      {
        Sid      = "AllowDataBucketList"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.data_bucket.arn
      },
      {
        # Cannot be scoped to a specific bucket — AWS limitation
        Sid      = "AllowListAllBuckets"
        Effect   = "Allow"
        Action   = "s3:ListAllMyBuckets"
        Resource = "*"
      }
    ]
  })
}

# SSM access — required for Session Manager to work
resource "aws_iam_role_policy_attachment" "ssm_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "s3_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.ec2_s3_policy.arn
}

# IAM roles can't attach directly to EC2 — must use instance profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "breach-lab-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# ============================================================
# EC2 INSTANCE — SSM only, IMDSv2 enforced, no key pair
# ============================================================
resource "aws_instance" "breach_lab_ec2" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  # No key_name — SSH is intentionally disabled

  metadata_options {
    http_tokens                 = "required"   # IMDSv2 enforced
    http_put_response_hop_limit = 1            # Blocks container escape → IMDS
    http_endpoint               = "enabled"
  }

  user_data = <<-EOF
    #!/bin/bash
    dnf update -y
    echo "breach-lab-ec2 initialized" > /tmp/init.txt
  EOF

  tags = {
    Name = "BreachLab-EC2"
  }
}
