provider "aws" {
  region = var.region
  profile = var.profile
}

# VPC
resource "aws_vpc" "lambda-remediation_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "lambda-remediation"
  }
}

# SG
resource "aws_security_group" "lambda-remediation_sg" {
  name = "lambda-remediation_sg"
  description = "sg which will be watched over by a lambda function"

  vpc_id = aws_vpc.lambda-remediation_vpc.id

  ingress {
    from_port = 80
    protocol = "tcp"
    to_port = 80
    cidr_blocks = ["-1"]
  }

  tags = {
    Name = "lambda-remediation"
  }
}


# CloudTrail bucket
resource "random_id" "bucket_suffix" {
  byte_length = 2
}
resource "aws_s3_bucket" "lambda-remediation_bucket" {
  bucket = "lambda-remediation-bucket-${random_id.bucket_suffix.dec}"
}

# Bucket Policy
data "aws_caller_identity" "current" {}
data "aws_iam_policy_document" "allow_cloudtrail_document" {
  statement {
    effect = "Allow"
    principals {
      identifiers = ["cloudtrail.amazonaws.com"]
      type = "Service"
    }
    actions = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.lambda-remediation_bucket.arn]
  }

  statement {
    effect = "Allow"
    principals {
      identifiers = ["cloudtrail.amazonaws.com"]
      type = "Service"
    }
    actions = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.lambda-remediation_bucket.arn}/CloudTrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test = "StringEquals"
      values = ["bucket-owner-full-control"]
      variable = "s3:x-amz-acl"
    }
  }
}

resource "aws_s3_bucket_policy" "lambda-remediation_bucket_policy" {
  bucket = aws_s3_bucket.lambda-remediation_bucket.id
  policy = data.aws_iam_policy_document.allow_cloudtrail_document.json
}


# CloudWatch Log group
resource "aws_cloudwatch_log_group" "lambda-remediation_loggroup" {
  name = "lambda-remediation_loggroup"

  retention_in_days = 1
}

# CloudWatch Log IAM
data "aws_iam_policy_document" "allow_cloudtrail_cloudwatch_document" {
  statement {
    effect  = "Allow"
    actions = ["logs:CreateLogStream"]

    resources = [
      "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.lambda-remediation_loggroup.name}:log-stream:*",
    ]
  }

  statement {
    effect  = "Allow"
    actions = ["logs:PutLogEvents"]

    resources = [
      "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:${aws_cloudwatch_log_group.lambda-remediation_loggroup.name}:log-stream:*",
    ]
  }
}

data "aws_iam_policy_document" "allow_cloudtrail_assume_role" {
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cloudtrail_cloudwatch_events_role" {
  assume_role_policy = data.aws_iam_policy_document.allow_cloudtrail_assume_role.json
}

resource "aws_iam_role_policy" "allow_cloudtrail_policy" {
  name = "cloudtrail_cloudwatch_events_policy"

  role = aws_iam_role.cloudtrail_cloudwatch_events_role.id
  policy = data.aws_iam_policy_document.allow_cloudtrail_cloudwatch_document.json
}


# CloudTrail
resource "aws_cloudtrail" "lambda-remediation_cloudtrail" {
  name = "lambda-remediation_cloudtrail"
  s3_bucket_name = aws_s3_bucket.lambda-remediation_bucket.id
  s3_key_prefix = "CloudTrail"

  include_global_service_events = true
  enable_log_file_validation = true
  enable_logging = true

  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.lambda-remediation_loggroup.arn
  cloud_watch_logs_role_arn = aws_iam_role.cloudtrail_cloudwatch_events_role.arn
}



# Remediation lambda role
data aws_iam_policy_document "allow_remediation_lambda"{
  statement {
    effect = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      identifiers = ["lambda.amazonaws.com"]
      type = "Service"
    }
  }
}

data aws_iam_policy_document "allow_sg_change" {
  statement {
    effect = "Allow"
    actions = ["ec2:RevokeSecurityGroupIngress"]
    resources = [
      "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:security-group/${aws_security_group.lambda-remediation_sg.id}"
    ]
  }

  statement {
    effect = "Allow"
    actions = ["logs:CreateLogGroup"]
    resources = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:*"]
  }

  statement {
    effect = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${aws_lambda_function.remediation-lambda.function_name}:*"]
  }
}

resource "aws_iam_role" "allow_sg_change_role" {
  assume_role_policy = data.aws_iam_policy_document.allow_remediation_lambda.json
}

resource "aws_iam_role_policy" "allow_sg_change_policy" {
  policy = data.aws_iam_policy_document.allow_sg_change.json
  role = aws_iam_role.allow_sg_change_role.id
}

# Remediation lambda
data "archive_file" "remediation-lambda" {
  output_path = "function.zip"
  type = "zip"
  source_file = "function.py"
}

resource "aws_lambda_function" "remediation-lambda" {
  function_name = "remediation-lambda"
  filename = data.archive_file.remediation-lambda.output_path
  handler = "function.lambda_handler"
  role = aws_iam_role.allow_sg_change_role.arn
  runtime = "python2.7"
  timeout = 60


  environment {
    variables = {
      security_group_id = aws_security_group.lambda-remediation_sg.id
    }
  }
}


# Lambda permission to be invoked by cloudwatch (or maybe event brdige actually?)
resource "aws_lambda_permission" "allow_invoking_lambda" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation-lambda.function_name
  principal = "events.amazonaws.com"
}

resource "aws_cloudwatch_event_target" "cloudwatch_lambda_target" {
  arn = aws_lambda_function.remediation-lambda.arn
  rule = aws_cloudwatch_event_rule.listen_to_sg_changes.name
}

# CloudWatch rule for lambda
resource "aws_cloudwatch_event_rule" "listen_to_sg_changes" {
  event_pattern = <<PATTERN
{
  "source": [
    "aws.ec2"
  ],
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "detail": {
    "eventSource": [
      "ec2.amazonaws.com"
    ],
    "eventName": [
      "AuthorizeSecurityGroupIngress",
      "AuthorizeSecurityGroupEgress",
      "RevokeSecurityGroupEgress",
      "RevokeSecurityGroupIngress",
      "CreateSecurityGroup",
      "DeleteSecurityGroup"
    ]
  }
}
PATTERN
  is_enabled = true
}
