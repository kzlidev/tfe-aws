# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.64"
    }
  }
}

provider "aws" {
  region = var.region
}

module "tfe" {
  source = "../.."

  lb_type                     = "alb"
  tfe_alb_tls_certificate_arn = aws_acm_certificate.alb_cert.arn

  # --- Common --- #
  friendly_name_prefix = var.friendly_name_prefix
  common_tags          = var.common_tags

  # --- Bootstrap --- #
  tfe_license_secret_arn             = aws_secretsmanager_secret.tfe_license_secret.arn
  tfe_encryption_password_secret_arn = aws_secretsmanager_secret.tfe_encryption_password_secret.arn
  tfe_tls_cert_secret_arn            = aws_secretsmanager_secret.tfe_tls_cert_secret.arn
  tfe_tls_privkey_secret_arn         = aws_secretsmanager_secret.tfe_tls_privkey_secret.arn
  tfe_tls_ca_bundle_secret_arn       = aws_secretsmanager_secret.tfe_tls_ca_bundle_secret.arn

  # --- TFE config settings --- #
  tfe_fqdn      = var.tfe_fqdn
  tfe_image_tag = var.tfe_image_tag

  # --- Networking --- #
  vpc_id        = aws_vpc.my_vpc.id
  lb_subnet_ids = [
    aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id, aws_subnet.public_subnet_3.id
  ]
  lb_is_internal = var.lb_is_internal
  ec2_subnet_ids = [
    aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id, aws_subnet.public_subnet_3.id
  ]
  rds_subnet_ids = [
    aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id, aws_subnet.private_subnet_3.id
  ]
  redis_subnet_ids = [
    aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id, aws_subnet.private_subnet_3.id
  ]
  cidr_allow_ingress_tfe_443 = var.cidr_allow_ingress_tfe_443
  cidr_allow_ingress_ec2_ssh = var.cidr_allow_ingress_ec2_ssh

  # --- DNS (optional) --- #
  create_route53_tfe_dns_record      = var.create_route53_tfe_dns_record
  route53_tfe_hosted_zone_name       = var.route53_tfe_hosted_zone_name
  route53_tfe_hosted_zone_is_private = var.route53_tfe_hosted_zone_is_private

  # --- Compute --- #
  ec2_os_distro      = var.ec2_os_distro
  asg_instance_count = var.asg_instance_count
  ec2_instance_size  = var.ec2_instance_size

  # --- Database --- #
  tfe_database_password_secret_arn = aws_secretsmanager_secret.tfe_database_password_secret.arn
  rds_skip_final_snapshot          = var.rds_skip_final_snapshot

  # --- Redis --- #
  tfe_redis_password_secret_arn = var.tfe_redis_password_secret_arn

  # --- Log forwarding (optional) --- #
  tfe_log_forwarding_enabled = var.tfe_log_forwarding_enabled
  log_fwd_destination_type   = var.log_fwd_destination_type
  s3_log_fwd_bucket_name     = var.s3_log_fwd_bucket_name
}
