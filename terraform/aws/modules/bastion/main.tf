locals {
  # Graviton families (t4g, m7g, c7g, ...) need the arm64 image.
  arch = can(regex("^[a-z]+[0-9]+g[a-z]*\\.", var.instance_type)) ? "arm64" : "x86_64"
}

data "aws_partition" "current" {}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-${local.arch}"
}

resource "aws_key_pair" "bastion" {
  key_name   = "${var.prefix}-bastion"
  public_key = var.ssh_public_key
  tags       = var.tags
}

# ---- Security groups ----
resource "aws_security_group" "bastion" {
  name        = "${var.prefix}-bastion"
  description = "Bastion: SSH only from allowed CIDRs, minimal egress"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.prefix}-bastion" })
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  for_each = toset(var.allowed_ssh_cidrs)

  security_group_id = aws_security_group.bastion.id
  description       = "SSH from allowed source"
  cidr_ipv4         = each.value
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  tags              = var.tags
}

resource "aws_vpc_security_group_egress_rule" "ssh_to_vpc" {
  security_group_id = aws_security_group.bastion.id
  description       = "SSH to private workloads"
  cidr_ipv4         = var.vpc_cidr
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  tags              = var.tags
}

resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.bastion.id
  description       = "HTTPS for package updates and SSM"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  tags              = var.tags
}

resource "aws_vpc_security_group_egress_rule" "http" {
  security_group_id = aws_security_group.bastion.id
  description       = "HTTP for package mirrors"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  tags              = var.tags
}

resource "aws_vpc_security_group_egress_rule" "ntp" {
  security_group_id = aws_security_group.bastion.id
  description       = "Amazon Time Sync"
  cidr_ipv4         = "169.254.169.123/32"
  from_port         = 123
  to_port           = 123
  ip_protocol       = "udp"
  tags              = var.tags
}

# SG for anything you put in the private subnets: SSH only from the bastion.
resource "aws_security_group" "workload" {
  name        = "${var.prefix}-private-workloads"
  description = "Private workloads: SSH only from bastion"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.prefix}-private-workloads" })
}

resource "aws_vpc_security_group_ingress_rule" "workload_ssh_from_bastion" {
  security_group_id            = aws_security_group.workload.id
  description                  = "SSH from bastion"
  referenced_security_group_id = aws_security_group.bastion.id
  from_port                    = 22
  to_port                      = 22
  ip_protocol                  = "tcp"
  tags                         = var.tags
}

resource "aws_vpc_security_group_egress_rule" "workload_all" {
  security_group_id = aws_security_group.workload.id
  description       = "All egress (via NAT)"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  tags              = var.tags
}

# ---- IAM: allow Session Manager as a no-inbound alternative to SSH ----
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "bastion" {
  name               = "${var.prefix}-bastion"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.bastion.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "bastion" {
  name = "${var.prefix}-bastion"
  role = aws_iam_role.bastion.name
  tags = var.tags
}

# ---- Instance ----
resource "aws_instance" "bastion" {
  ami                         = data.aws_ssm_parameter.al2023.insecure_value
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.bastion.id]
  key_name                    = aws_key_pair.bastion.key_name
  iam_instance_profile        = aws_iam_instance_profile.bastion.name
  associate_public_ip_address = false
  # ebs_optimized is left to the instance type: current generations are EBS-optimized by default, and t1/t2 refuse
  # an explicit true at launch.

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_size
    encrypted             = true
    kms_key_id            = var.kms_key_arn
    delete_on_termination = true
  }

  # First boot only: lock sshd down before anything that needs the network, then upgrade from the newest AL2023
  # release (its repositories are versioned, and the AMI's own release never sees a later fix). Provisioning then makes
  # `latest` permanent for dnf-automatic (hardening role).
  user_data = <<-USERDATA
    #!/bin/bash
    set -euo pipefail
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    systemctl restart sshd
    dnf -y --releasever=latest upgrade
  USERDATA

  tags = merge(var.tags, { Name = "${var.prefix}-bastion", Role = "bastion" })

  lifecycle {
    # ami: don't replace the host every time the AMI rolls forward. user_data: cloud-init runs it on the first boot
    # only, so a changed script would just stop and start an existing bastion for nothing.
    ignore_changes = [ami, user_data]
  }
}

resource "aws_eip" "bastion" {
  domain = "vpc"
  tags   = merge(var.tags, { Name = "${var.prefix}-bastion" })
}

resource "aws_eip_association" "bastion" {
  instance_id   = aws_instance.bastion.id
  allocation_id = aws_eip.bastion.id
}
