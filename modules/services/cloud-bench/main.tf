#----------------------------------------------------------
# Fetch & compute required data
#----------------------------------------------------------

data "aws_caller_identity" "me" {}

data "aws_organizations_organization" "org" {}

data "sysdig_secure_trusted_cloud_identity" "trusted_identity" {
  cloud_provider = "aws"
}

locals {
  // TODO Possibly `accounts` if stackset creates in master as well
  member_account_ids = var.is_organizational ? toset([for a in data.aws_organizations_organization.org.non_master_accounts : a.id]) : toset([])

  benchmark_task_name = var.is_organizational ? "Organization: ${data.aws_organizations_organization.org.id}" : data.aws_caller_identity.me.account_id

  accounts_scope_clause = var.is_organizational ? "aws.accountId in (\"${join("\", \"", local.member_account_ids)}\")" : "aws.accountId = \"${data.aws_caller_identity.me.account_id}\""
  regions_scope_clause  = length(var.regions) == 0 ? "" : " and aws.region in (\"${join("\", \"", var.regions)}\")"
}


#----------------------------------------------------------
# Configure Sysdig Backend
#----------------------------------------------------------

resource "sysdig_secure_cloud_account" "cloud_account" {
  for_each = var.is_organizational ? local.member_account_ids : [data.aws_caller_identity.me.account_id]

  account_id     = each.value
  cloud_provider = "aws"
  role_enabled   = "true"
}

locals {
  external_id = try(sysdig_secure_cloud_account.cloud_account[0].external_id, sysdig_secure_cloud_account.cloud_account[data.aws_caller_identity.me.account_id].external_id)
}

resource "sysdig_secure_benchmark_task" "benchmark_task" {
  name     = "Sysdig Secure for Cloud (AWS) - ${local.benchmark_task_name}"
  schedule = "0 6 * * *"
  schema   = "aws_foundations_bench-1.3.0"
  scope    = "${local.accounts_scope_clause}${local.regions_scope_clause}"

  # Creation of a task requires that the Cloud Account already exists in the backend, and has `role_enabled = true`
  depends_on = [sysdig_secure_cloud_account.cloud_account]
}


#----------------------------------------------------------
# If this is not an Organizational deploy, create role/polices directly
#----------------------------------------------------------

data "aws_iam_policy" "security_audit" {
  arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

data "aws_iam_policy_document" "trust_relationship" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [data.sysdig_secure_trusted_cloud_identity.trusted_identity.identity]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [local.external_id]
    }
  }
}

resource "aws_iam_role" "cloudbench_role" {
  count = var.is_organizational ? 0 : 1

  name               = "SysdigCloudBench"
  assume_role_policy = data.aws_iam_policy_document.trust_relationship.json
  tags               = var.tags
}


resource "aws_iam_role_policy_attachment" "cloudbench_security_audit" {
  count = var.is_organizational ? 0 : 1

  role       = aws_iam_role.cloudbench_role[0].id
  policy_arn = data.aws_iam_policy.security_audit.arn
}


#----------------------------------------------------------
# If this is an Organizational deploy, use a StackSet
#----------------------------------------------------------

resource "aws_cloudformation_stack_set" "stackset" {
  count = var.is_organizational ? 1 : 0
  name  = "SysdigCloudBench"

  auto_deployment {
    enabled                          = true
    retain_stacks_on_account_removal = false
  }

  template_body = <<TEMPLATE
Resources:
  SysdigCloudBench:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              AWS: [ ${data.sysdig_secure_trusted_cloud_identity.trusted_identity.identity} ]
            Action: [ 'sts:AssumeRole' ]
            Condition:
              StringEquals:
                sts:ExternalId: ${local.external_id}
      ManagedPolicyArns:
        - "arn:aws:iam::aws:policy/SecurityAudit"
      Tags
TEMPLATE
}
// TODO tags in CFT
