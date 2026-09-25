# Plan-level checks of the AWS stack with mock providers (no credentials, no cloud calls).
# Run: CLOUDSEED_TF_TESTS=1 python3 -m unittest tests.test_fix_core.TerraformModuleTests
#  or: terraform -chdir=terraform/aws init -backend=false && terraform -chdir=terraform/aws test

mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = { names = ["us-east-1a", "us-east-1b", "us-east-1c"] }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_region" {
    defaults = { name = "us-east-1", region = "us-east-1" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  mock_data "aws_ssm_parameter" {
    defaults = { value = "ami-0123456789abcdef0", insecure_value = "ami-0123456789abcdef0" }
  }
}

mock_provider "tls" {
  mock_data "tls_certificate" {
    defaults = { certificates = [{ sha1_fingerprint = "9e99a48a9960b14926bb7f3b02e22da2b0ab7280" }] }
  }
}

variables {
  name              = "acme"
  environment       = "dev"
  allowed_ssh_cidrs = ["203.0.113.7/32"]
  ssh_public_key    = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC test"
}

run "defaults_plan" {
  command = plan
}

run "refuses_ipv6_ssh_sources" {
  command = plan
  variables {
    allowed_ssh_cidrs = ["2001:db8::1/128"]
  }
  expect_failures = [var.allowed_ssh_cidrs]
}

run "refuses_the_internet_split_in_halves" {
  command = plan
  variables {
    allowed_ssh_cidrs = ["0.0.0.0/1", "128.0.0.0/1"]
  }
  expect_failures = [var.allowed_ssh_cidrs]
}

run "refuses_a_vpc_too_small_for_its_subnets" {
  command = plan
  variables {
    vpc_cidr = "10.0.0.0/25"
  }
  expect_failures = [var.vpc_cidr]
}

run "refuses_a_vpc_larger_than_aws_allows" {
  command = plan
  variables {
    vpc_cidr = "10.0.0.0/8"
  }
  expect_failures = [var.vpc_cidr]
}

# Values AWS only rejects at plan or apply time (after the VPC, NAT and KMS key exist) are refused by the variables,
# so `cloudseed setup --dry-run` (terraform validate) catches them too.
run "refuses_a_kms_window_kms_rejects" {
  command = plan
  variables {
    kms_deletion_window_in_days = 3
  }
  expect_failures = [var.kms_deletion_window_in_days]
}

run "refuses_a_root_volume_smaller_than_the_image" {
  command = plan
  variables {
    bastion_root_volume_size = 4
  }
  expect_failures = [var.bastion_root_volume_size]
}

run "refuses_an_impossible_vpn_port" {
  command = plan
  variables {
    vpn_port = 70000
  }
  expect_failures = [var.vpn_port]
}

run "refuses_vpn_port_zero" {
  command = plan
  variables {
    vpn_port = 0
  }
  expect_failures = [var.vpn_port]
}

run "refuses_a_fractional_vpn_port" {
  command = plan
  variables {
    vpn_port = 1194.5
  }
  expect_failures = [var.vpn_port]
}

# subnet_newbits: 1-12 (a /16 VPC with 12 gives /28 subnets, AWS's smallest); cloudseed's network check says the same
run "refuses_subnet_newbits_zero" {
  command = plan
  variables {
    subnet_newbits = 0
  }
  expect_failures = [var.subnet_newbits]
}

run "refuses_subnet_newbits_above_twelve" {
  command = plan
  variables {
    subnet_newbits = 13
  }
  expect_failures = [var.subnet_newbits]
}

run "refuses_a_fractional_subnet_newbits" {
  command = plan
  variables {
    subnet_newbits = 4.5
  }
  expect_failures = [var.subnet_newbits]
}

# A --tag Environment=... (cloudseed passes it in var.tags) applies to every resource; ManagedBy stays cloudseed.
run "environment_tag_is_a_default_a_tag_overrides" {
  command = plan
  variables {
    tags = { Environment = "production", ManagedBy = "someone-else", Team = "platform" }
  }
  assert {
    condition     = local.tags["Environment"] == "production" && local.tags["ManagedBy"] == "cloudseed" && local.tags["Team"] == "platform"
    error_message = "the user's Environment tag must win over var.environment, and ManagedBy must stay cloudseed"
  }
}

run "environment_tag_defaults_to_the_environment" {
  command = plan
  assert {
    condition     = local.tags["Environment"] == "dev" && local.tags["ManagedBy"] == "cloudseed"
    error_message = "without a tag, Environment is var.environment"
  }
}

run "refuses_retentions_cloudwatch_rejects" {
  command = plan
  variables {
    flow_log_retention_days = 45
    log_retention_days      = 100
  }
  expect_failures = [var.flow_log_retention_days, var.log_retention_days]
}

run "accepts_long_s3_retention" {
  command = plan
  variables {
    log_retention_days      = 4000
    flow_log_retention_days = 0
  }
}

run "refuses_eks_without_nodes" {
  command = plan
  variables {
    enable_kubernetes     = true
    kubernetes_node_count = 0
    kubernetes_node_min   = 0
  }
  expect_failures = [var.kubernetes_node_count]
}

run "refuses_malformed_versions_and_types" {
  command = plan
  variables {
    enable_kubernetes     = true
    kubernetes_version    = "v1.30"
    kubernetes_node_size  = "t3 medium"
    bastion_instance_type = "t3micro"
  }
  expect_failures = [var.kubernetes_version, var.kubernetes_node_size, var.bastion_instance_type]
}

run "refuses_an_out_of_range_subnet_stride" {
  command = plan
  variables {
    subnet_stride = 0
  }
  expect_failures = [var.subnet_stride]
}
