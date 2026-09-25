# Offline plan/apply checks of the AWS stack with mocked providers (no credentials, no cloud):
#   cd terraform/aws && terraform init -backend=false && terraform test
mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/mock" }
  }
  mock_resource "aws_iam_service_linked_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:mock" }
  }
  mock_resource "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/X", url = "oidc.eks.us-east-1.amazonaws.com/id/X" }
  }
  mock_resource "aws_eks_cluster" {
    defaults = { arn = "arn:aws:eks:us-east-1:123456789012:cluster/mock", identity = [{ oidc = [{ issuer = "https://oidc.eks.us-east-1.amazonaws.com/id/X" }] }] }
  }
  mock_resource "aws_eks_node_group" {
    defaults = { resources = [{ autoscaling_groups = [{ name = "asg-mock" }] }] }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::mockbucket" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-east-1:123456789012:mock" }
  }
  mock_data "aws_availability_zones" {
    defaults = {
      names    = ["us-east-1a", "us-east-1b", "us-east-1c"]
      zone_ids = ["use1-az1", "use1-az2", "use1-az4"]
    }
  }
  mock_data "aws_caller_identity" { defaults = { account_id = "123456789012" } }
  mock_data "aws_region" { defaults = { region = "us-east-1" } }
  mock_data "aws_partition" { defaults = { partition = "aws", dns_suffix = "amazonaws.com" } }
  mock_data "aws_iam_policy_document" { defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" } }
  mock_data "aws_ssm_parameter" { defaults = { value = "ami-12345678", insecure_value = "ami-12345678" } }
}

mock_provider "tls" {
  mock_data "tls_certificate" {
    defaults = { certificates = [{ sha1_fingerprint = "9e99a48a9960b14926bb7f3b02e22da2b0ab7280" }] }
  }
}

variables {
  name              = "cs"
  environment       = "t"
  allowed_ssh_cidrs = ["203.0.113.5/32"]
  ssh_public_key    = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBtest test"
}

# A brand-new environment with EKS, the VPN and Karpenter plans in one go (for_each keys are known at plan time).
run "fresh_kubernetes_vpn_karpenter" {
  command = plan
  variables {
    enable_kubernetes = true
    enable_vpn        = true
    platform_prereqs  = ["karpenter", "velero"]
  }
  assert {
    condition     = keys(module.kubernetes[0].irsa_role_arns) != null
    error_message = "kubernetes module did not plan"
  }
  assert {
    condition     = output.vpn_port == 1194 && output.vpn_type == "openvpn"
    error_message = "an OpenVPN host reports vpn_port"
  }
}

run "tailscale_reports_its_port" {
  command = plan
  variables {
    enable_vpn = true
    vpn_type   = "tailscale"
  }
  assert {
    condition     = output.vpn_port == 41641
    error_message = "a Tailscale VPN host listens on 41641 (what the security group opens), not the OpenVPN port"
  }
}

run "fips_kubernetes_vpn" {
  command = plan
  variables {
    fips_mode         = true
    enable_kubernetes = true
    enable_vpn        = true
    platform_prereqs  = ["karpenter", "velero"]
  }
  assert {
    condition     = output.fips_mode
    error_message = "fips_mode is reported"
  }
}

# The longest <name>-<env> prefix the CLI accepts (cli._config_problems) fits every AWS name limit: 33 characters with
# EKS (and everything `platform install` adds to it), 39 for the account baseline alone.
run "longest_prefix_with_eks" {
  command = plan
  variables {
    name              = "abcdefghijklmnop"
    environment       = "production-euw-1"
    enable_kubernetes = true
    enable_vpn        = true
    platform_prereqs  = ["karpenter", "velero"]
  }
}

run "longest_prefix_with_the_baseline" {
  command = plan
  variables {
    name        = "abcdefghijklmnopqrst"
    environment = "production-eu-west"
    enable_vpn  = true
  }
}

run "three_azs_nat_per_az" {
  command = plan
  variables {
    az_count           = 3
    single_nat_gateway = false
  }
  assert {
    condition     = length(local.azs) == 3 && length(output.nat_public_ips) == 3 && length(output.private_subnet_ids) == 3
    error_message = "three AZs with one NAT gateway each"
  }
}

run "single_az_without_eks" {
  command = plan
  variables {
    az_count = 1
  }
  assert {
    condition     = length(output.public_subnet_ids) == 1 && length(output.nat_public_ips) == 1
    error_message = "one AZ is fine without EKS"
  }
}

# Load balancers of the cluster find their subnets by tag: internal ones in the private tier, public ones in the public.
run "subnets_tagged_for_load_balancers" {
  command = plan
  module {
    source = "./modules/network"
  }
  variables {
    prefix                  = "cs-t"
    vpc_cidr                = "10.0.0.0/16"
    azs                     = ["us-east-1a", "us-east-1b"]
    subnet_newbits          = 4
    single_nat_gateway      = true
    create_data_subnets     = true
    enable_flow_logs        = false
    flow_log_retention_days = 30
    kms_key_arn             = "arn:aws:kms:us-east-1:123456789012:key/k"
    tags                    = {}
  }
  assert {
    condition     = alltrue([for s in aws_subnet.private : s.tags["kubernetes.io/role/internal-elb"] == "1" && !contains(keys(s.tags), "kubernetes.io/role/elb")])
    error_message = "private subnets carry kubernetes.io/role/internal-elb (and only that role)"
  }
  assert {
    condition     = alltrue([for s in aws_subnet.public : s.tags["kubernetes.io/role/elb"] == "1" && !contains(keys(s.tags), "kubernetes.io/role/internal-elb")])
    error_message = "public subnets carry kubernetes.io/role/elb (and only that role)"
  }
  assert {
    condition     = alltrue([for s in aws_subnet.data : !contains(keys(s.tags), "kubernetes.io/role/elb") && !contains(keys(s.tags), "kubernetes.io/role/internal-elb")])
    error_message = "no load balancer ever goes into the data tier"
  }
}

run "bastion_upgrades_from_the_latest_release" {
  command = plan
  module {
    source = "./modules/bastion"
  }
  variables {
    prefix            = "cs-t"
    vpc_id            = "vpc-1"
    vpc_cidr          = "10.0.0.0/16"
    subnet_id         = "subnet-1"
    allowed_ssh_cidrs = ["203.0.113.5/32"]
    ssh_public_key    = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBtest test"
    instance_type     = "t3.micro"
    root_volume_size  = 10
    kms_key_arn       = "arn:aws:kms:us-east-1:123456789012:key/k"
    tags              = {}
  }
  assert {
    condition     = strcontains(aws_instance.bastion.user_data, "dnf -y --releasever=latest upgrade")
    error_message = "the first boot must upgrade from the latest AL2023 release, not the AMI's pinned one"
  }
}

run "vpn_host_logs_in_as_ec2_user" {
  command = plan
  module {
    source = "./modules/vpn"
  }
  variables {
    prefix                     = "cs-t"
    vpc_id                     = "vpc-1"
    vpc_cidr                   = "10.0.0.0/16"
    subnet_id                  = "subnet-1"
    vpn_type                   = "openvpn"
    vpn_port                   = 1194
    bastion_security_group_id  = "sg-1"
    workload_security_group_id = "sg-2"
    key_name                   = "cs-t-bastion"
    instance_type              = "t3.micro"
    kms_key_arn                = "arn:aws:kms:us-east-1:123456789012:key/k"
    tags                       = {}
  }
  assert {
    condition     = strcontains(aws_instance.vpn.user_data, "name: ec2-user") && aws_instance.vpn.user_data_replace_on_change
    error_message = "the VPN host must create the ec2-user login every cloudseed command uses"
  }
}

run "base_apply" {
  command = apply
}

run "enable_kubernetes_on_existing" {
  command = apply
  variables {
    enable_kubernetes = true
    platform_prereqs  = ["karpenter"]
  }
}

run "then_add_vpn" {
  command = plan
  variables {
    enable_kubernetes = true
    enable_vpn        = true
    platform_prereqs  = ["karpenter"]
  }
}

run "security_hub_turns_on_aws_config" {
  command = plan
  variables {
    enable_security_hub = true
  }
  assert {
    condition     = local.enable_aws_config
    error_message = "Security Hub needs an AWS Config recorder"
  }
}

run "security_hub_without_config_when_asked" {
  command = plan
  variables {
    enable_security_hub = true
    enable_aws_config   = false
  }
  assert {
    condition     = !local.enable_aws_config
    error_message = "enable_aws_config = false must skip the recorder"
  }
}

run "eks_needs_two_azs" {
  command = plan
  variables {
    enable_kubernetes = true
    az_count          = 1
  }
  expect_failures = [var.enable_kubernetes]
}

run "node_count_within_bounds" {
  command = plan
  variables {
    enable_kubernetes     = true
    kubernetes_node_count = 9
  }
  expect_failures = [var.kubernetes_node_count]
}

run "az_count_larger_than_region" {
  command = plan
  variables {
    az_count = 4
  }
  expect_failures = [data.aws_availability_zones.available]
}

# In accounts where one of the first AZs cannot host EKS, the subnets move to supported AZs and the plan says so.
run "eks_skips_unsupported_azs_with_a_warning" {
  command = plan
  variables {
    enable_kubernetes = true
  }
  override_data {
    target = data.aws_availability_zones.available
    values = { names = ["us-east-1b", "us-east-1c"], zone_ids = ["use1-az1", "use1-az2"] }
  }
  override_data {
    target = data.aws_availability_zones.all
    values = { names = ["us-east-1a", "us-east-1b", "us-east-1c"], zone_ids = ["use1-az3", "use1-az1", "use1-az2"] }
  }
  assert {
    condition     = join(",", local.azs) == "us-east-1b,us-east-1c"
    error_message = "the EKS-unsupported AZ must be skipped"
  }
  expect_failures = [check.eks_availability_zones]
}

# ---- Subnet layout: changing az_count never re-addresses an existing subnet (subnet_stride = the first az_count) ----
run "network_layout_unchanged_without_a_stride" {
  command = plan
  module {
    source = "./modules/network"
  }
  variables {
    prefix                  = "cs-t"
    vpc_cidr                = "10.0.0.0/16"
    azs                     = ["us-east-1a", "us-east-1b"]
    subnet_newbits          = 4
    single_nat_gateway      = true
    create_data_subnets     = true
    enable_flow_logs        = false
    flow_log_retention_days = 30
    kms_key_arn             = "arn:aws:kms:us-east-1:123456789012:key/k"
    tags                    = {}
  }
  assert {
    condition = (join(",", aws_subnet.public[*].cidr_block) == "10.0.0.0/20,10.0.16.0/20" &&
      join(",", aws_subnet.private[*].cidr_block) == "10.0.32.0/20,10.0.48.0/20" &&
    join(",", aws_subnet.data[*].cidr_block) == "10.0.64.0/20,10.0.80.0/20")
    error_message = "the original layout (public i, private az_count+i, data 2*az_count+i) is kept for existing environments"
  }
}

run "network_third_az_is_appended" {
  command = plan
  module {
    source = "./modules/network"
  }
  variables {
    prefix                  = "cs-t"
    vpc_cidr                = "10.0.0.0/16"
    azs                     = ["us-east-1a", "us-east-1b", "us-east-1c"]
    subnet_newbits          = 4
    subnet_stride           = 2
    single_nat_gateway      = false
    create_data_subnets     = true
    enable_flow_logs        = false
    flow_log_retention_days = 30
    kms_key_arn             = "arn:aws:kms:us-east-1:123456789012:key/k"
    tags                    = {}
  }
  assert {
    condition = (join(",", aws_subnet.public[*].cidr_block) == "10.0.0.0/20,10.0.16.0/20,10.0.96.0/20" &&
      join(",", aws_subnet.private[*].cidr_block) == "10.0.32.0/20,10.0.48.0/20,10.0.112.0/20" &&
    join(",", aws_subnet.data[*].cidr_block) == "10.0.64.0/20,10.0.80.0/20,10.0.128.0/20")
    error_message = "the subnets of the first two AZs keep their blocks; the third AZ gets the next three"
  }
}

run "network_removed_az_leaves_the_rest_in_place" {
  command = plan
  module {
    source = "./modules/network"
  }
  variables {
    prefix                  = "cs-t"
    vpc_cidr                = "10.0.0.0/16"
    azs                     = ["us-east-1a", "us-east-1b"]
    subnet_newbits          = 4
    subnet_stride           = 3
    single_nat_gateway      = true
    create_data_subnets     = false
    enable_flow_logs        = false
    flow_log_retention_days = 30
    kms_key_arn             = "arn:aws:kms:us-east-1:123456789012:key/k"
    tags                    = {}
  }
  assert {
    condition = (join(",", aws_subnet.public[*].cidr_block) == "10.0.0.0/20,10.0.16.0/20" &&
    join(",", aws_subnet.private[*].cidr_block) == "10.0.48.0/20,10.0.64.0/20" && length(aws_subnet.data) == 0)
    error_message = "a 3-AZ layout that drops its third AZ keeps the other subnets where they were"
  }
}

run "stride_reaches_the_network" {
  command = plan
  variables {
    az_count      = 3
    subnet_stride = 2
  }
  assert {
    condition     = length(output.private_subnet_ids) == 3
    error_message = "three AZs on a two-AZ layout"
  }
}

# ---- Security baseline: account-wide half (one env per account) and regional half (one env per account and region) ----
run "second_env_same_region_manages_no_baseline" {
  command = plan
  variables {
    enable_account_baseline = false
  }
  assert {
    condition     = !local.regional_baseline && length(module.security_baseline) == 0 && output.cloudtrail_bucket == null
    error_message = "the regional half follows enable_account_baseline unless set: an existing second env stays as it was"
  }
}

run "env_in_a_new_region_keeps_the_regional_half" {
  command = plan
  variables {
    enable_account_baseline  = false
    enable_regional_baseline = true
    enable_security_hub      = true
  }
  assert {
    condition     = local.regional_baseline && length(module.security_baseline) == 1 && local.enable_aws_config
    error_message = "the regional half (GuardDuty, Access Analyzer, EBS encryption, Security Hub with Config) is managed without the account half"
  }
}

run "regional_half_only" {
  command = plan
  module {
    source = "./modules/security-baseline"
  }
  variables {
    prefix                 = "cs-t"
    account_id             = "123456789012"
    region                 = "us-west-2"
    kms_key_arn            = "arn:aws:kms:us-west-2:123456789012:key/k"
    manage_account         = false
    manage_region          = true
    enable_cloudtrail      = true
    enable_guardduty       = true
    enable_access_analyzer = true
    enable_security_hub    = true
    enable_aws_config      = true
    log_retention_days     = 365
    tags                   = {}
  }
  assert {
    condition = (length(aws_s3_account_public_access_block.this) == 0 && length(aws_iam_account_password_policy.this) == 0 &&
    length(aws_cloudtrail.this) == 0 && length(aws_guardduty_detector.this) == 1 && length(aws_accessanalyzer_analyzer.this) == 1)
    error_message = "no account-wide setting and no trail, but this region's GuardDuty and Access Analyzer"
  }
  assert {
    condition     = length(aws_s3_bucket.trail) == 1 && length(aws_config_delivery_channel.this) == 1 && length(aws_securityhub_account.this) == 1
    error_message = "AWS Config gets the log bucket even without CloudTrail"
  }
}

run "account_half_only" {
  command = plan
  module {
    source = "./modules/security-baseline"
  }
  variables {
    prefix                 = "cs-t"
    account_id             = "123456789012"
    region                 = "us-east-1"
    kms_key_arn            = "arn:aws:kms:us-east-1:123456789012:key/k"
    manage_account         = true
    manage_region          = false
    enable_cloudtrail      = true
    enable_guardduty       = true
    enable_access_analyzer = true
    enable_security_hub    = true
    enable_aws_config      = true
    log_retention_days     = 365
    tags                   = {}
  }
  assert {
    condition = (length(aws_s3_account_public_access_block.this) == 1 && length(aws_cloudtrail.this) == 1 &&
      length(aws_guardduty_detector.this) == 0 && length(aws_accessanalyzer_analyzer.this) == 0 &&
    length(aws_securityhub_account.this) == 0 && length(aws_config_configuration_recorder.this) == 0)
    error_message = "the account half manages no regional singleton"
  }
}

# The bastion's EKS access entry is usable: its role may call eks:DescribeCluster (update-kubeconfig) on the cluster.
run "bastion_can_describe_its_cluster" {
  command = plan
  variables {
    enable_kubernetes = true
  }
  assert {
    condition     = length(aws_iam_role_policy.bastion_eks) == 1
    error_message = "the bastion role gets eks:DescribeCluster with EKS"
  }
}

run "no_eks_policy_without_a_cluster" {
  command = plan
  assert {
    condition     = length(aws_iam_role_policy.bastion_eks) == 0 && output.vpn_instance_id == null
    error_message = "no cluster, no EKS permission; no VPN, no VPN instance"
  }
}
