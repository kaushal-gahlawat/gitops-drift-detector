###############################################################################
# GitOps Drift Detector — Sample AWS Infrastructure (Terraform)
# This is the "desired state" that the drift detector compares against.
###############################################################################

terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state backend — replace with your bucket name
  backend "s3" {
    bucket         = "kaushal-drift-tfstate"
    key            = "gitops-drift-demo/terraform.tfstate"
    region         = "ap-south-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Project     = "GitOpsDriftDemo"
      Environment = var.environment
    }
  }
}

###############################################################################
# Variables
###############################################################################

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "ap-south-1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "staging"

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production."
  }
}

variable "ec2_instance_type" {
  description = "EC2 instance type for the demo app server"
  type        = string
  default     = "t3.micro"
}

###############################################################################
# Networking
###############################################################################

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "drift-demo-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = { Name = "drift-demo-public-subnet" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "drift-demo-igw" }
}

###############################################################################
# Security Group — monitored for drift
###############################################################################

resource "aws_security_group" "app" {
  name        = "drift-demo-app-sg"
  description = "Security group for the demo application server"
  vpc_id      = aws_vpc.main.id

  # Intentionally strict — any manual console changes will be detected
  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "drift-demo-app-sg" }
}

###############################################################################
# EC2 Instance — monitored for drift (instance_type, ami, etc.)
###############################################################################

data "aws_ami" "amazon_linux_2023" {
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

resource "aws_instance" "app" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.ec2_instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.app.id]
  monitoring             = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"   # IMDSv2 enforced
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30
    encrypted             = true
    delete_on_termination = true
  }

  user_data = base64encode(<<-EOT
    #!/bin/bash
    yum update -y
    yum install -y nginx
    systemctl enable nginx
    systemctl start nginx
  EOT
  )

  tags = { Name = "drift-demo-app-server" }

  lifecycle {
    ignore_changes = [ami, user_data]   # AMI updates happen separately
  }
}

###############################################################################
# S3 Bucket — monitored for public access, encryption, versioning
###############################################################################

resource "aws_s3_bucket" "assets" {
  bucket = "drift-demo-assets-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "drift-demo-assets" }
}

resource "aws_s3_bucket_versioning" "assets" {
  bucket = aws_s3_bucket.assets.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

###############################################################################
# IAM Role — monitored for assume-role-policy drift
###############################################################################

resource "aws_iam_role" "app" {
  name = "drift-demo-app-role"
  path = "/app/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  max_session_duration = 3600
  tags                 = { Name = "drift-demo-app-role" }
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "app" {
  name = "drift-demo-app-profile"
  role = aws_iam_role.app.name
}

###############################################################################
# RDS (optional demo resource) — monitored for multi-az, encryption, deletion protection
###############################################################################

# Uncomment to demo RDS drift detection
# resource "aws_db_instance" "main" {
#   identifier             = "drift-demo-db"
#   engine                 = "postgres"
#   engine_version         = "15.4"
#   instance_class         = "db.t3.micro"
#   allocated_storage      = 20
#   storage_encrypted      = true
#   deletion_protection    = true
#   multi_az               = false
#   publicly_accessible    = false
#   skip_final_snapshot    = true
#
#   tags = { Name = "drift-demo-db" }
# }

###############################################################################
# IAM Role for the Drift Detector itself (least-privilege)
###############################################################################

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "drift_detector" {
  name = "GitOpsDriftDetector"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = {
        Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
      }
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:/kaushal-gahlawat/gitops-drift-detector:*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "drift_detector" {
  name = "DriftDetectorPolicy"
  role = aws_iam_role.drift_detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2ReadOnly"
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetBucketVersioning",
          "s3:GetBucketEncryption",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetBucketAcl",
          "s3:ListBucket",
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMReadOnly"
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:ListRolePolicies",
          "iam:GetRolePolicy",
        ]
        Resource = "*"
      },
      {
        Sid    = "RDSReadOnly"
        Effect = "Allow"
        Action = ["rds:DescribeDBInstances"]
        Resource = "*"
      },
      {
        Sid    = "ELBReadOnly"
        Effect = "Allow"
        Action = ["elasticloadbalancing:DescribeLoadBalancers"]
        Resource = "*"
      },
      {
        Sid    = "TFStateRead"
        Effect = "Allow"
        Action = ["s3:GetObject"]
        Resource = "arn:aws:s3:::your-tf-state-bucket/*"
      }
    ]
  })
}

###############################################################################
# Outputs
###############################################################################

output "drift_detector_role_arn" {
  description = "ARN to use as AWS_DRIFT_DETECTOR_ROLE_ARN secret in GitHub Actions"
  value       = aws_iam_role.drift_detector.arn
}

output "app_instance_id" {
  description = "EC2 instance ID to watch for drift"
  value       = aws_instance.app.id
}

output "app_security_group_id" {
  description = "Security group ID to watch for drift"
  value       = aws_security_group.app.id
}

output "assets_bucket_name" {
  description = "S3 bucket name to watch for drift"
  value       = aws_s3_bucket.assets.id
}
