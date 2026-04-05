output "data_bucket_name" {
  description = "Name of the data bucket (allowed access)"
  value       = aws_s3_bucket.data_bucket.bucket
}

output "sensitive_bucket_name" {
  description = "Name of the sensitive bucket (must be blocked)"
  value       = aws_s3_bucket.sensitive_bucket.bucket
}

output "log_bucket_name" {
  description = "Name of the CloudTrail log bucket"
  value       = aws_s3_bucket.log_bucket.bucket
}

output "ec2_instance_id" {
  description = "EC2 instance ID — use this to start an SSM session"
  value       = aws_instance.breach_lab_ec2.id
}

output "ec2_role_arn" {
  description = "ARN of the IAM role attached to EC2"
  value       = aws_iam_role.ec2_role.arn
}

output "cloudtrail_name" {
  description = "CloudTrail trail name"
  value       = aws_cloudtrail.breach_lab_trail.name
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.breach_lab_detector.id
}

output "aws_account_id" {
  description = "AWS account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "imdsv2_enforced" {
  description = "Confirms IMDSv2 enforcement on the EC2 instance"
  value = {
    http_tokens     = aws_instance.breach_lab_ec2.metadata_options[0].http_tokens
    hop_limit       = aws_instance.breach_lab_ec2.metadata_options[0].http_put_response_hop_limit
    endpoint_status = aws_instance.breach_lab_ec2.metadata_options[0].http_endpoint
  }
}
