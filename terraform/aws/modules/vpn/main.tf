# VPN host in the public subnet (OpenVPN server or Tailscale subnet router), configured by Ansible.
variable "prefix" { type = string }
variable "vpc_id" { type = string }
variable "vpc_cidr" { type = string }
variable "subnet_id" { type = string }
variable "vpn_type" { type = string }
variable "vpn_port" { type = number }
variable "allowed_ssh_cidrs" { type = list(string) }
variable "bastion_security_group_id" { type = string }
variable "workload_security_group_id" { type = string }
variable "key_name" { type = string }
variable "instance_type" { type = string }
variable "kms_key_arn" { type = string }
variable "tags" { type = map(string) }

locals {
  arch = can(regex("^[a-z]+[0-9]+g[a-z]*\\.", var.instance_type)) ? "arm64" : "amd64"
}

data "aws_partition" "current" {}

# Ubuntu 24.04 LTS (OpenVPN + easy-rsa are packaged; Amazon Linux does not ship them). Canonical's image logs in as
# `ubuntu`, but cloudseed reaches every AWS host as `ec2-user` (the bastion's AL2023 user; provisioning, `vpn add-user`,
# `connect` and `scan` all use it, and the hardening role writes `AllowUsers <that user>`), so cloud-init below renames
# the image's default user to ec2-user. The key pair's key, passwordless sudo and the shell move with it.
data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/${local.arch}/hvm/ebs-gp3/ami-id"
}

resource "aws_security_group" "vpn" {
  name        = "${var.prefix}-vpn"
  description = "VPN host: VPN port from anywhere, SSH from allowed CIDRs and bastion"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.prefix}-vpn" })
}

resource "aws_vpc_security_group_ingress_rule" "openvpn" {
  count = var.vpn_type == "openvpn" ? 1 : 0

  security_group_id = aws_security_group.vpn.id
  description       = "OpenVPN"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = var.vpn_port
  to_port           = var.vpn_port
  ip_protocol       = "udp"
}

resource "aws_vpc_security_group_ingress_rule" "tailscale" {
  count = var.vpn_type == "tailscale" ? 1 : 0

  security_group_id = aws_security_group.vpn.id
  description       = "Tailscale direct connections"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 41641
  to_port           = 41641
  ip_protocol       = "udp"
}

resource "aws_vpc_security_group_ingress_rule" "ssh_allowed" {
  for_each = toset(var.allowed_ssh_cidrs)

  security_group_id = aws_security_group.vpn.id
  description       = "SSH from allowed source"
  cidr_ipv4         = each.value
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "ssh_bastion" {
  security_group_id            = aws_security_group.vpn.id
  description                  = "SSH from bastion"
  referenced_security_group_id = var.bastion_security_group_id
  from_port                    = 22
  to_port                      = 22
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.vpn.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# VPN clients (NATed behind the VPN host) may reach private workloads.
resource "aws_vpc_security_group_ingress_rule" "workloads_from_vpn" {
  security_group_id            = var.workload_security_group_id
  description                  = "All traffic from VPN clients"
  referenced_security_group_id = aws_security_group.vpn.id
  ip_protocol                  = "-1"
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "vpn" {
  name               = "${var.prefix}-vpn"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.vpn.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "vpn" {
  name = "${var.prefix}-vpn"
  role = aws_iam_role.vpn.name
  tags = var.tags
}

resource "aws_instance" "vpn" {
  ami                         = data.aws_ssm_parameter.ubuntu.insecure_value
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.vpn.id]
  key_name                    = var.key_name
  iam_instance_profile        = aws_iam_instance_profile.vpn.name
  associate_public_ip_address = false
  source_dest_check           = false # routes/NATs client traffic into the VPC
  # ebs_optimized is left to the instance type (current generations are EBS-optimized by default; t1/t2 refuse true)

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 10
    encrypted             = true
    kms_key_id            = var.kms_key_arn
    delete_on_termination = true
  }

  # Full default_user dict: cloud-init merges it over the image's, and a partial one could drop sudo/groups.
  user_data                   = <<-USERDATA
    #cloud-config
    system_info:
      default_user:
        name: ec2-user
        lock_passwd: true
        gecos: cloudseed
        groups: [adm, sudo]
        sudo: ["ALL=(ALL) NOPASSWD:ALL"]
        shell: /bin/bash
  USERDATA
  user_data_replace_on_change = true # users are created on first boot only: a host built without this is rebuilt

  tags = merge(var.tags, { Name = "${var.prefix}-vpn", Role = "vpn" })

  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_eip" "vpn" {
  domain = "vpc"
  tags   = merge(var.tags, { Name = "${var.prefix}-vpn" })
}

resource "aws_eip_association" "vpn" {
  instance_id   = aws_instance.vpn.id
  allocation_id = aws_eip.vpn.id
}

output "public_ip" { value = aws_eip.vpn.public_ip }
output "instance_id" { value = aws_instance.vpn.id }
output "security_group_id" { value = aws_security_group.vpn.id }
output "iam_role_arn" { value = aws_iam_role.vpn.arn }
