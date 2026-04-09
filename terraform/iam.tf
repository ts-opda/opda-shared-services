data "aws_caller_identity" "current" {}

# The OIDC provider is created once by opda-ops and shared across all repos.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_role" "github_actions" {
  name = "opda-shared-services-github-actions"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {
        Federated = data.aws_iam_openid_connect_provider.github.arn
      }
      Condition = {
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_repo}:ref:refs/heads/main",
            "repo:${var.github_repo}:environment:dev",
          ]
        }
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
      }
    }]
  })

  tags = {
    Project   = "opda-shared-services"
    ManagedBy = "terraform"
  }
}

resource "aws_iam_role_policy" "github_actions" {
  name = "publish"
  role = aws_iam_role.github_actions.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # ── ECR ────────────────────────────────────────────────────────────────
      {
        Sid      = "ECRAuthToken"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ECRSharedRepo"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage",
          "ecr:CompleteLayerUpload", "ecr:CreateRepository",
          "ecr:DeleteLifecyclePolicy", "ecr:DescribeRepositories",
          "ecr:GetDownloadUrlForLayer", "ecr:GetLifecyclePolicy",
          "ecr:GetRepositoryPolicy", "ecr:InitiateLayerUpload",
          "ecr:ListTagsForResource", "ecr:PutImage",
          "ecr:PutLifecyclePolicy", "ecr:SetRepositoryPolicy",
          "ecr:UploadLayerPart",
        ]
        Resource = aws_ecr_repository.shared.arn
      },
      # ── Terraform state ────────────────────────────────────────────────────
      {
        Sid      = "TerraformStateBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = "arn:aws:s3:::ops-terraform-state-${data.aws_caller_identity.current.account_id}"
      },
      {
        Sid    = "TerraformStateObjects"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = "arn:aws:s3:::ops-terraform-state-${data.aws_caller_identity.current.account_id}/opda-shared-services/*"
      },
      {
        Sid    = "TerraformStateLock"
        Effect = "Allow"
        Action = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/ops-terraform-state-lock"
      },
    ]
  })
}

output "github_actions_role_arn" {
  value       = aws_iam_role.github_actions.arn
  description = "Set this as AWS_ROLE_ARN in the opda-shared-services GitHub Actions environment"
}
