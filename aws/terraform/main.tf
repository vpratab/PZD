terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  type = list(string)
}

variable "private_subnet_ids" {
  type = list(string)
}

variable "allowed_ingress_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

variable "domain_name" {
  type = string
}

variable "certificate_arn" {
  type        = string
  description = "Issued ACM certificate ARN for domain_name in the same region as the ALB."
}

variable "instance_type" {
  type    = string
  default = "c5.xlarge"
}

variable "enclave_cpu_count" {
  type    = number
  default = 2
}

variable "enclave_memory_mib" {
  type    = number
  default = 2048
}

variable "pzdr_measurement" {
  type        = string
  description = "Expected Nitro PCR0/ImageSha384 measurement for the signed EIF."
}

variable "tags" {
  type    = map(string)
  default = { Project = "PZDR" }
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "pzdr_kek" {
  description             = "PZDR DEK wrapping key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RootAccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "EnclaveAttestedDecrypt"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.gateway.arn }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = "*"
        Condition = {
          StringEqualsIgnoreCase = {
            "kms:RecipientAttestation:ImageSha384" = var.pzdr_measurement
          }
        }
      }
    ]
  })
}

resource "aws_iam_role" "gateway" {
  name = "pzdr-gateway-parent"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.gateway.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "gateway" {
  name = "pzdr-gateway-instance-profile"
  role = aws_iam_role.gateway.name
}

resource "aws_security_group" "alb" {
  name        = "pzdr-alb-sg"
  description = "PZDR public ALB"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_ingress_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

resource "aws_security_group" "gateway" {
  name        = "pzdr-gateway-parent-sg"
  description = "PZDR EC2 parent partition"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 8090
    to_port         = 8090
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-kernel-default-x86_64"]
  }
}

resource "aws_instance" "gateway" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = var.instance_type
  subnet_id              = var.private_subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.gateway.id]
  iam_instance_profile   = aws_iam_instance_profile.gateway.name

  enclave_options {
    enabled = true
  }

  user_data = templatefile("${path.module}/userdata.sh", {
    enclave_cpu    = var.enclave_cpu_count
    enclave_memory = var.enclave_memory_mib
    measurement    = var.pzdr_measurement
    kms_key_arn    = aws_kms_key.pzdr_kek.arn
  })

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }

  tags = merge(var.tags, { Name = "pzdr-gateway" })
}

resource "aws_lb" "gateway" {
  name               = "pzdr-gateway-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = var.public_subnet_ids
  security_groups    = [aws_security_group.alb.id]
  tags               = var.tags
}

resource "aws_lb_target_group" "gateway" {
  name        = "pzdr-gateway-tg"
  port        = 8090
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = 15
    timeout             = 3
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

resource "aws_lb_target_group_attachment" "gateway" {
  target_group_arn = aws_lb_target_group.gateway.arn
  target_id        = aws_instance.gateway.id
  port             = 8090
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.gateway.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway.arn
  }
}

resource "aws_cloudwatch_metric_alarm" "enclave_failure" {
  alarm_name          = "pzdr-enclave-failure"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "EnclaveTerminations"
  namespace           = "PZDR"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "PZDR enclave termination count exceeded zero."
  tags                = var.tags
}

output "gateway_url" {
  value = "https://${var.domain_name}"
}

output "alb_dns_name" {
  value = aws_lb.gateway.dns_name
}

output "instance_id" {
  value = aws_instance.gateway.id
}

output "kms_key_arn" {
  value = aws_kms_key.pzdr_kek.arn
}

output "measurement" {
  value = var.pzdr_measurement
}
