# GovCloud (aws-us-gov): every ARN the stack writes must carry the partition of the credentials, never the commercial
# "arn:aws:" (KMS refuses such a key-policy principal, and the managed policies / EKS access policy do not exist there).
# Offline, with mocked providers:  cd terraform/aws && terraform init -backend=false && terraform test
mock_provider "aws" {
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/11111111-2222-3333-4444-555555555555" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws-us-gov:iam::123456789012:role/mock", name = "mock" }
  }
  mock_resource "aws_iam_service_linked_role" {
    defaults = { arn = "arn:aws-us-gov:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws-us-gov:logs:us-gov-west-1:123456789012:log-group:mock" }
  }
  mock_resource "aws_iam_openid_connect_provider" {
    defaults = { arn = "arn:aws-us-gov:iam::123456789012:oidc-provider/oidc.eks.us-gov-west-1.amazonaws.com/id/X", url = "oidc.eks.us-gov-west-1.amazonaws.com/id/X" }
  }
  mock_resource "aws_eks_cluster" {
    defaults = { arn = "arn:aws-us-gov:eks:us-gov-west-1:123456789012:cluster/mock", identity = [{ oidc = [{ issuer = "https://oidc.eks.us-gov-west-1.amazonaws.com/id/X" }] }] }
  }
  mock_resource "aws_eks_node_group" {
    defaults = { resources = [{ autoscaling_groups = [{ name = "asg-mock" }] }] }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws-us-gov:s3:::mockbucket" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws-us-gov:sqs:us-gov-west-1:123456789012:mock" }
  }
  mock_data "aws_availability_zones" {
    defaults = {
      names    = ["us-gov-west-1a", "us-gov-west-1b", "us-gov-west-1c"]
      zone_ids = ["usgw1-az1", "usgw1-az2", "usgw1-az3"]
    }
  }
  mock_data "aws_caller_identity" { defaults = { account_id = "123456789012" } }
  mock_data "aws_region" { defaults = { region = "us-gov-west-1" } }
  mock_data "aws_partition" { defaults = { partition = "aws-us-gov", dns_suffix = "amazonaws.com" } }
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
  environment       = "gov"
  allowed_ssh_cidrs = ["203.0.113.5/32"]
  ssh_public_key    = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQtest test"
}

# The whole stack applies (mocked) in GovCloud with every optional part on.
run "govcloud_full_stack" {
  command = apply
  variables {
    fips_mode           = true
    enable_kubernetes   = true
    enable_vpn          = true
    enable_security_hub = true
    platform_prereqs    = ["karpenter", "velero"]
  }
  assert {
    condition     = local.partition == "aws-us-gov"
    error_message = "the stack reads the partition of the credentials"
  }
  assert {
    condition     = strcontains(aws_iam_role_policy.bastion_eks[0].policy, "eks:DescribeCluster") && strcontains(aws_iam_role_policy.bastion_eks[0].policy, "arn:aws-us-gov:eks:")
    error_message = "the bastion role may describe (only) its cluster"
  }
}

# China and the isolated regions are flagged (cloudseed setup refuses them before anything is created).
run "china_is_flagged" {
  command = plan
  override_data {
    target = data.aws_partition.current
    values = { partition = "aws-cn", dns_suffix = "amazonaws.com.cn" }
  }
  expect_failures = [check.supported_partition]
}

run "kms_key_policy_uses_the_partition" {
  command = plan
  module {
    source = "./modules/kms"
  }
  variables {
    prefix                  = "cs-gov"
    account_id              = "123456789012"
    region                  = "us-gov-west-1"
    deletion_window_in_days = 7
    allow_aws_config        = true
    tags                    = {}
  }
  assert {
    condition = alltrue(flatten([for st in data.aws_iam_policy_document.key.statement : concat(
      [for p in st.principals : [for id in p.identifiers : !startswith(id, "arn:aws:")]],
      [for c in st.condition : [for v in c.values : !startswith(v, "arn:aws:")]],
    )]))
    error_message = "no commercial ARN in the key policy"
  }
  assert {
    condition     = contains(flatten([for st in data.aws_iam_policy_document.key.statement : [for p in st.principals : p.identifiers]]), "arn:aws-us-gov:iam::123456789012:root")
    error_message = "the account root principal is a GovCloud ARN"
  }
}

run "bastion_ssm_policy_uses_the_partition" {
  command = plan
  module {
    source = "./modules/bastion"
  }
  variables {
    prefix            = "cs-gov"
    vpc_id            = "vpc-1"
    vpc_cidr          = "10.0.0.0/16"
    subnet_id         = "subnet-1"
    allowed_ssh_cidrs = ["203.0.113.5/32"]
    ssh_public_key    = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQtest test"
    instance_type     = "t3.micro"
    root_volume_size  = 10
    kms_key_arn       = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/k"
    tags              = {}
  }
  assert {
    condition     = aws_iam_role_policy_attachment.ssm.policy_arn == "arn:aws-us-gov:iam::aws:policy/AmazonSSMManagedInstanceCore"
    error_message = "SSM managed policy in the GovCloud partition"
  }
}

run "vpn_ssm_policy_uses_the_partition" {
  command = plan
  module {
    source = "./modules/vpn"
  }
  variables {
    prefix                     = "cs-gov"
    vpc_id                     = "vpc-1"
    vpc_cidr                   = "10.0.0.0/16"
    subnet_id                  = "subnet-1"
    vpn_type                   = "openvpn"
    vpn_port                   = 1194
    allowed_ssh_cidrs          = ["203.0.113.5/32"]
    bastion_security_group_id  = "sg-1"
    workload_security_group_id = "sg-2"
    key_name                   = "cs-gov-bastion"
    instance_type              = "t3.micro"
    kms_key_arn                = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/k"
    tags                       = {}
  }
  assert {
    condition     = aws_iam_role_policy_attachment.ssm.policy_arn == "arn:aws-us-gov:iam::aws:policy/AmazonSSMManagedInstanceCore"
    error_message = "SSM managed policy in the GovCloud partition"
  }
}

run "baseline_arns_use_the_partition" {
  command = plan
  module {
    source = "./modules/security-baseline"
  }
  variables {
    prefix                 = "cs-gov"
    account_id             = "123456789012"
    region                 = "us-gov-west-1"
    kms_key_arn            = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/k"
    manage_account         = true
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
    condition     = local.trail_arn == "arn:aws-us-gov:cloudtrail:us-gov-west-1:123456789012:trail/cs-gov-trail"
    error_message = "the bucket policy's aws:SourceArn must match the GovCloud trail"
  }
  assert {
    condition     = startswith(aws_securityhub_standards_subscription.fsbp[0].standards_arn, "arn:aws-us-gov:securityhub:us-gov-west-1::standards/")
    error_message = "Security Hub standard in the GovCloud partition"
  }
}

run "eks_arns_use_the_partition" {
  command = plan
  module {
    source = "./modules/kubernetes"
  }
  variables {
    prefix              = "cs-gov"
    vpc_id              = "vpc-1"
    vpc_cidr            = "10.0.0.0/16"
    private_subnet_ids  = ["subnet-1", "subnet-2"]
    kubernetes_version  = null
    node_instance_type  = "t3.medium"
    node_desired        = 2
    node_min            = 1
    node_max            = 4
    public_endpoint     = false
    public_access_cidrs = ["203.0.113.5/32"]
    admin_roles         = { "arn:aws-us-gov:iam::123456789012:role/cs-gov-bastion" = "arn:aws-us-gov:iam::123456789012:role/cs-gov-bastion" }
    kms_key_arn         = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/k"
    log_retention_days  = 365
    account_id          = "123456789012"
    region              = "us-gov-west-1"
    platform_prereqs    = ["karpenter", "velero"]
    fips_mode           = true
    tags                = {}
  }
  assert {
    condition = alltrue(concat(
      [aws_iam_role_policy_attachment.cluster.policy_arn == "arn:aws-us-gov:iam::aws:policy/AmazonEKSClusterPolicy"],
      [for a in aws_iam_role_policy_attachment.node : startswith(a.policy_arn, "arn:aws-us-gov:iam::aws:policy/")],
      [for a in aws_iam_role_policy_attachment.karpenter_node : startswith(a.policy_arn, "arn:aws-us-gov:iam::aws:policy/")],
      [for a in aws_iam_role_policy_attachment.irsa_managed : startswith(a.policy_arn, "arn:aws-us-gov:iam::aws:policy/")],
      [for a in aws_eks_access_policy_association.admin : a.policy_arn == "arn:aws-us-gov:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"],
    ))
    error_message = "managed policy and EKS access policy ARNs in the GovCloud partition"
  }
  assert {
    condition     = length(aws_iam_role_policy_attachment.node) == 4 && length(aws_iam_role_policy_attachment.karpenter_node) == 4
    error_message = "the node roles keep their four managed policies"
  }
  assert {
    condition     = !strcontains(aws_iam_role_policy.lb_controller.policy, "arn:aws:") && strcontains(aws_iam_role_policy.lb_controller.policy, "arn:aws-us-gov:elasticloadbalancing:")
    error_message = "the vendored load balancer controller policy is rewritten for the partition"
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.lb_controller.policy).Version == "2012-10-17" && length(jsondecode(aws_iam_role_policy.lb_controller.policy).Statement) == 16
    error_message = "the vendored load balancer controller policy is the upstream document"
  }
  assert {
    condition     = alltrue([for st in data.aws_iam_policy_document.external_dns.statement : alltrue([for r in st.resources : !startswith(r, "arn:aws:")])])
    error_message = "external-dns's Route53 ARN in the GovCloud partition"
  }
}
