# Plan/apply-level checks of the GCP state bucket with mock providers (no credentials, no cloud calls).
# Run: CLOUDSEED_TF_TESTS=1 python3 -m unittest tests.test_fix_core.TerraformModuleTests
#  or: terraform -chdir=terraform/gcp-bootstrap init -backend=false && terraform -chdir=terraform/gcp-bootstrap test

mock_provider "google" {}
mock_provider "random" {}

variables {
  project_id = "proj-123456"
  location   = "us-east1"
  labels     = { managedby = "cloudseed" }
}

run "ordinary_prefix_keeps_its_name" {
  command = apply
  variables {
    prefix = "cs-dev"
  }
  assert {
    condition     = startswith(output.bucket, "cs-dev-tfstate-")
    error_message = "a valid prefix keeps the historical <prefix>-tfstate-<hex> name"
  }
}

# Cloud Storage refuses bucket names that start with "goog" or contain "google" (or a close misspelling).
run "google_like_prefix_gets_a_neutral_stem" {
  command = apply
  variables {
    prefix = "google-lab-dev"
  }
  assert {
    condition     = can(regex("^cs-[0-9a-f]{8}-tfstate-", output.bucket)) && !strcontains(output.bucket, "google")
    error_message = "a google-like prefix never reaches the state bucket name"
  }
}

run "goog_prefix_gets_a_neutral_stem" {
  command = apply
  variables {
    prefix = "goog-dev"
  }
  assert {
    condition     = !startswith(output.bucket, "goog")
    error_message = "a goog prefix never starts the state bucket name"
  }
}

run "long_prefix_is_capped" {
  command = apply
  variables {
    prefix = "abcdefghijklmnopqrstuvwx-production-europe-west-a"
  }
  assert {
    condition     = length(output.bucket) <= 63
    error_message = "bucket names are at most 63 characters"
  }
}
