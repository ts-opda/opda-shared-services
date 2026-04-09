# The `key` is intentionally omitted here and must be supplied at init time:
#
#   terraform init -backend-config="key=opda-shared-services/terraform.tfstate"
#
# This follows the same pattern as other repos in this project so all state
# lives under the same S3 bucket.

terraform {
  backend "s3" {
    bucket         = "ops-terraform-state-355653384628"
    region         = "eu-west-2"
    use_lockfile   = true
  }
}
